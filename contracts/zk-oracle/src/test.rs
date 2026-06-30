#![cfg(test)]

use super::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Bytes, BytesN, Env, Vec};

use ark_bn254::{Bn254, Fq, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, VerifyingKey as ArkVk};
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};

//
// ---- arkworks proof generation + EIP-197 serialization ----
//

/// A trivial 2-public-input circuit: `(a + b) * 1 = c`, with `a`, `b` public and
/// `c` a witness. Satisfiable for any `(a, b)`, giving a verifying key whose
/// `gamma_abc_g1` has exactly 3 entries — matching the oracle's two signals.
#[derive(Clone)]
struct SumCircuit {
    a: Option<Fr>,
    b: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for SumCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a = cs.new_input_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_input_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_witness_variable(|| {
            Ok(self.a.ok_or(SynthesisError::AssignmentMissing)?
                + self.b.ok_or(SynthesisError::AssignmentMissing)?)
        })?;
        cs.enforce_constraint(lc!() + a + b, lc!() + Variable::One, lc!() + c)?;
        Ok(())
    }
}

/// Big-endian 32-byte serialization of a prime-field element.
fn pf_be<F: PrimeField>(f: &F) -> [u8; 32] {
    let be = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// EIP-197 G1 encoding: `be(X) ‖ be(Y)` (64 zero bytes for the identity).
fn g1_bytes(p: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    if p.infinity {
        return out;
    }
    out[..32].copy_from_slice(&pf_be(&p.x));
    out[32..].copy_from_slice(&pf_be(&p.y));
    out
}

/// EIP-197 G2 encoding: `be(X) ‖ be(Y)`, each `Fp2 = be(c1) ‖ be(c0)`.
fn g2_bytes(p: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    if p.infinity {
        return out;
    }
    out[..32].copy_from_slice(&pf_be::<Fq>(&p.x.c1));
    out[32..64].copy_from_slice(&pf_be::<Fq>(&p.x.c0));
    out[64..96].copy_from_slice(&pf_be::<Fq>(&p.y.c1));
    out[96..].copy_from_slice(&pf_be::<Fq>(&p.y.c0));
    out
}

fn to_soroban_vk(e: &Env, vk: &ArkVk<Bn254>) -> VerifyingKey {
    let mut ic = Vec::new(e);
    for p in vk.gamma_abc_g1.iter() {
        ic.push_back(BytesN::from_array(e, &g1_bytes(p)));
    }
    VerifyingKey {
        alpha: BytesN::from_array(e, &g1_bytes(&vk.alpha_g1)),
        beta: BytesN::from_array(e, &g2_bytes(&vk.beta_g2)),
        gamma: BytesN::from_array(e, &g2_bytes(&vk.gamma_g2)),
        delta: BytesN::from_array(e, &g2_bytes(&vk.delta_g2)),
        ic,
    }
}

/// A complete set of test vectors for one circuit + proof.
struct Vectors {
    vk: VerifyingKey,
    public_inputs: Bytes,
    proof: Bytes,
    chain_id: u64,
    payload_hash: BytesN<32>,
}

/// Runs a fresh Groth16 setup (`seed`) and proves the statement
/// `(chain_id, payload mod r)`, returning vectors in the contract's encoding.
fn prove(e: &Env, seed: u64, chain_id: u64, payload: [u8; 32]) -> Vectors {
    let a_val = Fr::from(chain_id);
    let b_val = Fr::from_be_bytes_mod_order(&payload);

    let mut rng = StdRng::seed_from_u64(seed);
    let (pk, ark_vk) =
        Groth16::<Bn254>::circuit_specific_setup(SumCircuit { a: None, b: None }, &mut rng)
            .unwrap();
    let ark_proof = Groth16::<Bn254>::prove(
        &pk,
        SumCircuit {
            a: Some(a_val),
            b: Some(b_val),
        },
        &mut rng,
    )
    .unwrap();
    // Sanity-check on the arkworks side before feeding the contract.
    assert!(Groth16::<Bn254>::verify(&ark_vk, &[a_val, b_val], &ark_proof).unwrap());

    let mut pi = [0u8; 64];
    pi[..32].copy_from_slice(&pf_be(&a_val));
    pi[32..].copy_from_slice(&pf_be(&b_val));

    let mut pf = [0u8; 256];
    pf[..64].copy_from_slice(&g1_bytes(&ark_proof.a));
    pf[64..192].copy_from_slice(&g2_bytes(&ark_proof.b));
    pf[192..].copy_from_slice(&g1_bytes(&ark_proof.c));

    Vectors {
        vk: to_soroban_vk(e, &ark_vk),
        public_inputs: Bytes::from_array(e, &pi),
        proof: Bytes::from_array(e, &pf),
        chain_id,
        payload_hash: BytesN::from_array(e, &pf_be(&b_val)),
    }
}

fn deploy(e: &Env, vk: &VerifyingKey) -> ZkOracleClient<'static> {
    let owner = Address::generate(e);
    let id = e.register(ZkOracle, (owner, vk.clone()));
    ZkOracleClient::new(e, &id)
}

//
// ---- tests ----
//

#[test]
fn verifies_real_proof_and_records_statement() {
    let e = Env::default();
    let v = prove(&e, 1, 42, [0xab; 32]);
    let client = deploy(&e, &v.vk);

    assert!(!client.is_proven(&v.chain_id, &v.payload_hash));

    client.receive_proof(&v.public_inputs, &v.proof);

    assert!(client.is_proven(&v.chain_id, &v.payload_hash));
    // Unrelated statements remain unproven.
    assert!(!client.is_proven(&v.chain_id, &BytesN::from_array(&e, &[0u8; 32])));
    assert!(!client.is_proven(&99u64, &v.payload_hash));
}

#[test]
fn idempotent_resubmit_skips_verification() {
    let e = Env::default();
    let v = prove(&e, 1, 7, [0x11; 32]);
    let client = deploy(&e, &v.vk);

    client.receive_proof(&v.public_inputs, &v.proof);
    assert!(client.is_proven(&v.chain_id, &v.payload_hash));

    // Already proven: even a garbage proof is a no-op (verification is skipped).
    let broken = Bytes::from_array(&e, &[0u8; 256]);
    client.receive_proof(&v.public_inputs, &broken);
    assert!(client.is_proven(&v.chain_id, &v.payload_hash));
}

#[test]
fn verifying_key_getter_returns_stored_key() {
    let e = Env::default();
    let v = prove(&e, 1, 1, [0x01; 32]);
    let client = deploy(&e, &v.vk);
    assert_eq!(client.verifying_key(), v.vk);
}

#[test]
#[should_panic]
fn rejects_tampered_proof() {
    let e = Env::default();
    let v = prove(&e, 1, 1, [0x22; 32]);
    let client = deploy(&e, &v.vk);

    let mut pf = [0u8; 256];
    v.proof.copy_into_slice(&mut pf);
    pf[200] ^= 0x01; // flip a byte inside C
    client.receive_proof(&v.public_inputs, &Bytes::from_array(&e, &pf));
}

#[test]
#[should_panic]
fn rejects_proof_for_wrong_statement() {
    let e = Env::default();
    let v = prove(&e, 1, 1, [0x22; 32]);
    let client = deploy(&e, &v.vk);

    // Valid proof, but the claimed chain_id no longer matches the proof.
    let mut pi = [0u8; 64];
    v.public_inputs.copy_into_slice(&mut pi);
    pi[31] ^= 0x01;
    client.receive_proof(&Bytes::from_array(&e, &pi), &v.proof);
}

#[test]
#[should_panic]
fn rejects_bad_public_input_length() {
    let e = Env::default();
    let v = prove(&e, 1, 1, [0x33; 32]);
    let client = deploy(&e, &v.vk);
    client.receive_proof(&Bytes::from_array(&e, &[0u8; 32]), &v.proof);
}

#[test]
#[should_panic]
fn rejects_bad_proof_length() {
    let e = Env::default();
    let v = prove(&e, 1, 1, [0x44; 32]);
    let client = deploy(&e, &v.vk);
    client.receive_proof(&v.public_inputs, &Bytes::from_array(&e, &[0u8; 100]));
}

#[test]
#[should_panic]
fn rejects_chain_id_exceeding_u64() {
    let e = Env::default();
    let v = prove(&e, 1, 1, [0x55; 32]);
    let client = deploy(&e, &v.vk);

    let mut pi = [0u8; 64];
    v.public_inputs.copy_into_slice(&mut pi);
    pi[0] = 0x01; // a high byte of the chain_id word => doesn't fit u64
    client.receive_proof(&Bytes::from_array(&e, &pi), &v.proof);
}

#[test]
#[should_panic]
fn constructor_rejects_wrong_ic_length() {
    let e = Env::default();
    let v = prove(&e, 1, 1, [0x66; 32]);

    let mut bad_ic = Vec::new(&e);
    bad_ic.push_back(v.vk.ic.get(0).unwrap());
    bad_ic.push_back(v.vk.ic.get(1).unwrap());
    let bad_vk = VerifyingKey {
        ic: bad_ic,
        ..v.vk.clone()
    };

    let owner = Address::generate(&e);
    e.register(ZkOracle, (owner, bad_vk));
}

#[test]
fn owner_can_rotate_verifying_key() {
    let e = Env::default();
    e.mock_all_auths();

    let v1 = prove(&e, 1, 5, [0x77; 32]);
    let client = deploy(&e, &v1.vk);

    // Rotate to an independently-generated key (different trusted setup).
    let v2 = prove(&e, 2, 8, [0x88; 32]);
    client.set_verifying_key(&v2.vk);
    assert_eq!(client.verifying_key(), v2.vk);

    // A proof under the new key verifies and is recorded.
    client.receive_proof(&v2.public_inputs, &v2.proof);
    assert!(client.is_proven(&v2.chain_id, &v2.payload_hash));
}
