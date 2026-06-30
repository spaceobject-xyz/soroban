#![no_std]

//! Groth16 (BN254) zero-knowledge proof oracle for the cross-chain intent
//! bridge.
//!
//! [`ZkOracle::receive_proof`] verifies a Groth16 proof *on-chain* against a
//! verifying key fixed at deployment, and records the proven
//! `(chain_id, payload_hash)` statement. Other contracts (e.g. the escrow's
//! `claim` path) then gate actions on [`ZkOracle::is_proven`] instead of
//! re-running the cryptography themselves.
//!
//! ## Curve & encoding (BN254 / EVM-compatible)
//!
//! BN254 (alt_bn128) is the EVM curve, so proofs from the EVM ZK toolchain
//! (Circom/snarkjs) and the SDK's `crypto().bn254()` host functions agree on the
//! Ethereum/EIP-197 serialization used here:
//! - **G1** (64 bytes): `be(X) ‖ be(Y)`, each a 32-byte big-endian field element.
//! - **G2** (128 bytes): `be(X) ‖ be(Y)`, each an `Fp2 = be(c1) ‖ be(c0)`.
//! - **Fr** (32 bytes): big-endian, reduced mod the scalar field order `r`.
//!
//! - `proof` is `A ‖ B ‖ C` = `G1 ‖ G2 ‖ G1` = **256 bytes**.
//! - `public_inputs` is the two public signals `chain_id ‖ payload_hash`, each a
//!   32-byte big-endian field element = **64 bytes**. `chain_id` must fit in a
//!   `u64` (its high 24 bytes are zero); `payload_hash` is taken mod `r`, so the
//!   circuit must expose the same reduced value.
//!
//! ## Trust model
//!
//! Submitting a proof is *permissionless* — a valid proof is its own
//! authorization. The only privileged action is rotating the verifying key,
//! which is owner-gated; until ownership is renounced, consumers trust the owner
//! not to install a key that accepts forged proofs. Anti-replay for the
//! *actions* a proof unlocks (e.g. releasing escrow once) belongs in the
//! consuming contract — recording a proven fact is idempotent by nature.

use soroban_sdk::crypto::bn254::{Bn254Fr, Bn254G1Affine, Bn254G2Affine};
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, vec,
    Address, Bytes, BytesN, Env, Vec,
};
use stellar_access::ownable::{set_owner, Ownable};
use stellar_macros::only_owner;

/// Serialized size of a BN254 G1 point (`be(X) ‖ be(Y)`), in bytes.
const G1_LEN: usize = 64;
/// Serialized size of a BN254 G2 point (`be(X) ‖ be(Y)`, each `Fp2`), in bytes.
const G2_LEN: usize = 128;
/// Serialized size of a single field-element public signal, in bytes.
const SIGNAL_LEN: usize = 32;

/// Number of public signals: `chain_id` and `payload_hash`.
const NUM_SIGNALS: usize = 2;
/// Expected `public_inputs` length (`chain_id ‖ payload_hash`), in bytes.
const PUBLIC_INPUTS_LEN: usize = NUM_SIGNALS * SIGNAL_LEN;
/// Expected `proof` length (`A ‖ B ‖ C`), in bytes.
const PROOF_LEN: usize = G1_LEN + G2_LEN + G1_LEN;
/// Required length of the verifying key's `ic` vector: one point per public
/// signal, plus the constant term.
const IC_LEN: u32 = NUM_SIGNALS as u32 + 1;

/// Ledgers per day at the ~5s close rate, for storage TTL bookkeeping.
const DAY_IN_LEDGERS: u32 = 17_280;
/// How far to bump instance storage (the verifying key) on each write.
const INSTANCE_TTL_EXTEND: u32 = 7 * DAY_IN_LEDGERS;
const INSTANCE_TTL_THRESHOLD: u32 = INSTANCE_TTL_EXTEND - DAY_IN_LEDGERS;
/// How far to bump a recorded proof's TTL when it is first stored.
const PROOF_TTL_EXTEND: u32 = 30 * DAY_IN_LEDGERS;
const PROOF_TTL_THRESHOLD: u32 = PROOF_TTL_EXTEND - DAY_IN_LEDGERS;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// `public_inputs` was not `chain_id ‖ payload_hash` (64 bytes), or
    /// `chain_id` did not fit in a `u64`.
    InvalidPublicInputs = 1,
    /// `proof` was not `A ‖ B ‖ C` (256 bytes), or the pairing check failed.
    InvalidProof = 2,
    /// The verifying key's `ic` length did not match the number of signals.
    InvalidVerifyingKey = 3,
}

/// Groth16 verifying key over BN254, in the SDK's EIP-197 byte encoding.
///
/// `ic` holds one G1 point per public signal plus the constant term, so its
/// length is [`IC_LEN`] (`NUM_SIGNALS + 1`).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifyingKey {
    /// `alpha` in G1.
    pub alpha: BytesN<64>,
    /// `beta` in G2.
    pub beta: BytesN<128>,
    /// `gamma` in G2.
    pub gamma: BytesN<128>,
    /// `delta` in G2.
    pub delta: BytesN<128>,
    /// `gamma_abc_g1`: the constant term followed by one G1 point per signal.
    pub ic: Vec<BytesN<64>>,
}

/// Emitted once, when a `(chain_id, payload_hash)` statement is first proven.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofVerified {
    #[topic]
    pub chain_id: u64,
    #[topic]
    pub payload_hash: BytesN<32>,
}

/// Emitted when the owner rotates the verifying key.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifyingKeyUpdated {}

#[contracttype]
enum DataKey {
    /// The Groth16 [`VerifyingKey`].
    Vk,
    /// Marker that a `(chain_id, payload_hash)` statement has been proven.
    Proven(u64, BytesN<32>),
}

#[contract]
pub struct ZkOracle;

#[contractimpl]
impl ZkOracle {
    /// Initializes the oracle with its `owner` and the Groth16 verifying `key`.
    ///
    /// Panics with [`Error::InvalidVerifyingKey`] if `key.ic` does not have one
    /// point per public signal plus the constant term ([`IC_LEN`] entries).
    pub fn __constructor(e: &Env, owner: Address, key: VerifyingKey) {
        if key.ic.len() != IC_LEN {
            panic_with_error!(e, Error::InvalidVerifyingKey);
        }
        set_owner(e, &owner);
        e.storage().instance().set(&DataKey::Vk, &key);
    }

    /// Verifies a Groth16 proof and records its `(chain_id, payload_hash)`
    /// statement.
    ///
    /// `public_inputs` must be the two public signals `chain_id ‖ payload_hash`
    /// (64 bytes); `proof` must be `A ‖ B ‖ C` (256 bytes) — see the module
    /// docs for the exact byte layout. On a passing pairing check the statement
    /// is persisted so [`is_proven`](Self::is_proven) returns `true`, and
    /// [`ProofVerified`] is emitted.
    ///
    /// Submission is permissionless. The call is idempotent: re-submitting an
    /// already-proven statement is a no-op (no re-verification, no duplicate
    /// event). Panics with [`Error::InvalidPublicInputs`] / [`Error::InvalidProof`]
    /// on a malformed input or a failed proof.
    pub fn receive_proof(e: &Env, public_inputs: Bytes, proof: Bytes) {
        // ---- Parse and domain-check the public inputs. ----
        if public_inputs.len() != PUBLIC_INPUTS_LEN as u32 {
            panic_with_error!(e, Error::InvalidPublicInputs);
        }
        let mut pi = [0u8; PUBLIC_INPUTS_LEN];
        public_inputs.copy_into_slice(&mut pi);
        let mut s0 = [0u8; SIGNAL_LEN];
        let mut s1 = [0u8; SIGNAL_LEN];
        s0.copy_from_slice(&pi[..SIGNAL_LEN]);
        s1.copy_from_slice(&pi[SIGNAL_LEN..]);

        // `chain_id` is the first signal; it must fit in a u64 (high bytes zero).
        if s0[..SIGNAL_LEN - 8].iter().any(|&b| b != 0) {
            panic_with_error!(e, Error::InvalidPublicInputs);
        }
        let mut cid = [0u8; 8];
        cid.copy_from_slice(&s0[SIGNAL_LEN - 8..]);
        let chain_id = u64::from_be_bytes(cid);
        let payload_hash = BytesN::from_array(e, &s1);

        // ---- Idempotency: a statement proven once stays proven. ----
        let key = DataKey::Proven(chain_id, payload_hash.clone());
        if e.storage().persistent().has(&key) {
            return;
        }

        // ---- Verify the proof on-chain. ----
        if !Self::verify_groth16(e, &s0, &s1, &proof) {
            panic_with_error!(e, Error::InvalidProof);
        }

        // ---- Record the proven statement. ----
        e.storage().persistent().set(&key, &true);
        e.storage()
            .persistent()
            .extend_ttl(&key, PROOF_TTL_THRESHOLD, PROOF_TTL_EXTEND);
        e.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND);

        ProofVerified {
            chain_id,
            payload_hash,
        }
        .publish(e);
    }

    /// Returns whether a proof has been recorded for `(chain_id, payload_hash)`.
    ///
    /// A recorded proof is subject to the persistent-storage TTL; if it is
    /// allowed to expire it must be re-submitted (cheap and idempotent while
    /// still live).
    pub fn is_proven(e: &Env, chain_id: u64, payload_hash: BytesN<32>) -> bool {
        e.storage()
            .persistent()
            .has(&DataKey::Proven(chain_id, payload_hash))
    }

    /// Returns the Groth16 verifying key currently in use.
    pub fn verifying_key(e: &Env) -> VerifyingKey {
        e.storage()
            .instance()
            .get(&DataKey::Vk)
            .expect("verifying key should be set")
    }

    /// Replaces the verifying key. Owner-only.
    ///
    /// Lets the owner rotate to a new circuit's key without migrating recorded
    /// proofs. The owner can install a key that accepts forged proofs, so
    /// consumers trust the owner until ownership is renounced (see
    /// [`Ownable::renounce_ownership`]).
    #[only_owner]
    pub fn set_verifying_key(e: &Env, key: VerifyingKey) {
        if key.ic.len() != IC_LEN {
            panic_with_error!(e, Error::InvalidVerifyingKey);
        }
        e.storage().instance().set(&DataKey::Vk, &key);
        e.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND);

        VerifyingKeyUpdated {}.publish(e);
    }

    /// Checks the Groth16 pairing equation for proof `A ‖ B ‖ C` against the
    /// stored verifying key and the two public signals `s0`, `s1`.
    ///
    /// Computes `vk_x = ic[0] + s0·ic[1] + s1·ic[2]` and returns whether
    /// `e(-A, B) · e(alpha, beta) · e(vk_x, gamma) · e(C, delta) == 1`.
    fn verify_groth16(e: &Env, s0: &[u8; 32], s1: &[u8; 32], proof: &Bytes) -> bool {
        if proof.len() != PROOF_LEN as u32 {
            panic_with_error!(e, Error::InvalidProof);
        }
        let mut pf = [0u8; PROOF_LEN];
        proof.copy_into_slice(&mut pf);
        let mut a = [0u8; G1_LEN];
        let mut b = [0u8; G2_LEN];
        let mut c = [0u8; G1_LEN];
        a.copy_from_slice(&pf[..G1_LEN]);
        b.copy_from_slice(&pf[G1_LEN..G1_LEN + G2_LEN]);
        c.copy_from_slice(&pf[G1_LEN + G2_LEN..]);

        let proof_a = Bn254G1Affine::from_bytes(BytesN::from_array(e, &a));
        let proof_b = Bn254G2Affine::from_bytes(BytesN::from_array(e, &b));
        let proof_c = Bn254G1Affine::from_bytes(BytesN::from_array(e, &c));

        let VerifyingKey {
            alpha,
            beta,
            gamma,
            delta,
            ic,
        } = Self::verifying_key(e);
        let alpha = Bn254G1Affine::from_bytes(alpha);
        let beta = Bn254G2Affine::from_bytes(beta);
        let gamma = Bn254G2Affine::from_bytes(gamma);
        let delta = Bn254G2Affine::from_bytes(delta);
        let ic0 = Bn254G1Affine::from_bytes(ic.get(0).unwrap());
        let ic1 = Bn254G1Affine::from_bytes(ic.get(1).unwrap());
        let ic2 = Bn254G1Affine::from_bytes(ic.get(2).unwrap());

        let fr0 = Bn254Fr::from_bytes(BytesN::from_array(e, s0));
        let fr1 = Bn254Fr::from_bytes(BytesN::from_array(e, s1));

        let bn = e.crypto().bn254();
        // vk_x = ic0 + s0·ic1 + s1·ic2
        let acc = bn.g1_msm(vec![e, ic1, ic2], vec![e, fr0, fr1]);
        let vk_x = bn.g1_add(&ic0, &acc);

        // e(-A, B) · e(alpha, beta) · e(vk_x, gamma) · e(C, delta) == 1
        bn.pairing_check(
            vec![e, -proof_a, alpha, vk_x, proof_c],
            vec![e, proof_b, beta, gamma, delta],
        )
    }
}

//
// ---- Extensions ----
//

#[contractimpl(contracttrait)]
impl Ownable for ZkOracle {}

mod test;
