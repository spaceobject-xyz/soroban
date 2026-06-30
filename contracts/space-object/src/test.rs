#![cfg(test)]

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::token::{StellarAssetClient, TokenClient};
use soroban_sdk::{contract, contractimpl, contracttype, BytesN, Env};

/// Minimal stand-in for the real `ZkOracle`: lets a test mark a
/// `(chain_id, payload_hash)` statement proven and answers `is_proven`.
#[contract]
pub struct MockZkOracle;

#[contracttype]
enum MockKey {
    Proven(u64, BytesN<32>),
}

#[contractimpl]
impl MockZkOracle {
    pub fn set_proven(e: Env, chain_id: u64, payload_hash: BytesN<32>) {
        e.storage()
            .persistent()
            .set(&MockKey::Proven(chain_id, payload_hash), &true);
    }

    pub fn is_proven(e: Env, chain_id: u64, payload_hash: BytesN<32>) -> bool {
        e.storage()
            .persistent()
            .get(&MockKey::Proven(chain_id, payload_hash))
            .unwrap_or(false)
    }
}

fn setup(e: &Env) -> (SpaceObjectClient<'static>, Address, Address, Address) {
    let owner = Address::generate(e);
    let fee_collector = Address::generate(e);
    let zk_oracle = e.register(MockZkOracle, ());
    let config = ProtocolConfig {
        fee_bps: 30,
        fee_collector: fee_collector.clone(),
        zk_oracle: zk_oracle.clone(),
    };
    let id = e.register(SpaceObject, (owner.clone(), config));
    (
        SpaceObjectClient::new(e, &id),
        zk_oracle,
        owner,
        fee_collector,
    )
}

/// Deploys a Stellar Asset Contract and mints `amount` to `to`.
fn fund(e: &Env, to: &Address, amount: i128) -> Address {
    let issuer = Address::generate(e);
    let token = e.register_stellar_asset_contract_v2(issuer).address();
    StellarAssetClient::new(e, &token).mint(to, &amount);
    token
}

#[test]
fn constructor_sets_owner_and_config() {
    let e = Env::default();
    let (client, _oracle, owner, fee_collector) = setup(&e);

    assert_eq!(client.get_owner(), Some(owner));
    let config = client.get_config();
    assert_eq!(config.fee_bps, 30);
    assert_eq!(config.fee_collector, fee_collector);
}

#[test]
fn owner_can_update_config() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, oracle, _owner, fee_collector) = setup(&e);

    client.set_config(&ProtocolConfig {
        fee_bps: 50,
        fee_collector,
        zk_oracle: oracle,
    });

    assert_eq!(client.get_config().fee_bps, 50);
}

#[test]
#[should_panic]
fn set_config_rejects_excessive_fee() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, oracle, _owner, fee_collector) = setup(&e);

    client.set_config(&ProtocolConfig {
        fee_bps: MAX_FEE_BPS + 1,
        fee_collector,
        zk_oracle: oracle,
    });
}

#[test]
fn owner_can_pause_and_unpause() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, _oracle, owner, _fc) = setup(&e);

    assert!(!client.paused());
    client.pause(&owner);
    assert!(client.paused());
    client.unpause(&owner);
    assert!(!client.paused());
}

#[test]
fn create_order_escrows_funds() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, _oracle, _owner, _fc) = setup(&e);

    let taker = Address::generate(&e);
    let token_in = fund(&e, &taker, 1_000);
    let token_client = TokenClient::new(&e, &token_in);

    let token_out = BytesN::from_array(&e, &[9u8; 32]);
    let recipient = BytesN::from_array(&e, &[7u8; 32]);
    let deadline = e.ledger().timestamp() + 3_600;

    let id = client.create_order(
        &taker, &token_in, &600i128, &token_out, &590i128, &recipient, &10u64, &deadline, &1u64,
    );

    // Funds moved from the taker into the escrow.
    assert_eq!(token_client.balance(&taker), 400);
    assert_eq!(token_client.balance(&client.address), 600);

    // The returned id is the content hash of the order's terms.
    let expected = Order {
        taker: taker.clone(),
        token_in: token_in.clone(),
        amount_in: 600,
        token_out: token_out.clone(),
        amount_out: 590,
        recipient: recipient.clone(),
        dest_chain: 10,
        deadline,
        nonce: 1,
        status: OrderStatus::Open,
    };
    assert_eq!(id, order_id(&e, &expected));

    // The order is persisted under that id as Open with the supplied terms.
    let stored: Order = e.as_contract(&client.address, || {
        e.storage()
            .persistent()
            .get(&DataKey::Order(id.clone()))
            .unwrap()
    });
    assert_eq!(stored, expected);
}

#[test]
fn distinct_nonce_yields_distinct_id() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, _oracle, _owner, _fc) = setup(&e);

    let taker = Address::generate(&e);
    let token_in = fund(&e, &taker, 2_000);
    let token_out = BytesN::from_array(&e, &[9u8; 32]);
    let recipient = BytesN::from_array(&e, &[7u8; 32]);
    let deadline = e.ledger().timestamp() + 3_600;

    let id1 = client.create_order(
        &taker, &token_in, &600i128, &token_out, &590i128, &recipient, &10u64, &deadline, &1u64,
    );
    let id2 = client.create_order(
        &taker, &token_in, &600i128, &token_out, &590i128, &recipient, &10u64, &deadline, &2u64,
    );

    assert_ne!(id1, id2);
}

#[test]
#[should_panic]
fn duplicate_order_rejected() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, _oracle, _owner, _fc) = setup(&e);

    let taker = Address::generate(&e);
    let token_in = fund(&e, &taker, 2_000);
    let token_out = BytesN::from_array(&e, &[9u8; 32]);
    let recipient = BytesN::from_array(&e, &[7u8; 32]);
    let deadline = e.ledger().timestamp() + 3_600;

    // Identical terms + nonce hash to the same id -> the second call is rejected.
    client.create_order(
        &taker, &token_in, &600i128, &token_out, &590i128, &recipient, &10u64, &deadline, &1u64,
    );
    client.create_order(
        &taker, &token_in, &600i128, &token_out, &590i128, &recipient, &10u64, &deadline, &1u64,
    );
}

#[test]
#[should_panic]
fn create_order_rejects_zero_amount() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, _oracle, _owner, _fc) = setup(&e);

    let taker = Address::generate(&e);
    let token_in = fund(&e, &taker, 1_000);
    let token_out = BytesN::from_array(&e, &[0u8; 32]);
    let recipient = BytesN::from_array(&e, &[0u8; 32]);

    client.create_order(
        &taker,
        &token_in,
        &0i128,
        &token_out,
        &590i128,
        &recipient,
        &10u64,
        &(e.ledger().timestamp() + 3_600),
        &1u64,
    );
}

#[test]
#[should_panic]
fn create_order_rejects_past_deadline() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, _oracle, _owner, _fc) = setup(&e);

    let taker = Address::generate(&e);
    let token_in = fund(&e, &taker, 1_000);
    let token_out = BytesN::from_array(&e, &[0u8; 32]);
    let recipient = BytesN::from_array(&e, &[0u8; 32]);

    e.ledger().set_timestamp(1_000);
    client.create_order(
        &taker, &token_in, &600i128, &token_out, &590i128, &recipient, &10u64, &500u64, &1u64,
    );
}

#[test]
#[should_panic]
fn create_order_blocked_when_paused() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, _oracle, owner, _fc) = setup(&e);

    client.pause(&owner);

    let taker = Address::generate(&e);
    let token_in = fund(&e, &taker, 1_000);
    let token_out = BytesN::from_array(&e, &[0u8; 32]);
    let recipient = BytesN::from_array(&e, &[0u8; 32]);

    // The `#[when_not_paused]` guard fires before the body.
    client.create_order(
        &taker,
        &token_in,
        &600i128,
        &token_out,
        &590i128,
        &recipient,
        &10u64,
        &(e.ledger().timestamp() + 3_600),
        &1u64,
    );
}

/// Opens an order escrowing `amount_in` of a freshly funded token, and returns
/// the order id, the escrow token, and a fill receipt for it whose repayment
/// target is `repayment`.
fn open_order(
    e: &Env,
    client: &SpaceObjectClient<'static>,
    amount_in: i128,
    dest_chain: u64,
    repayment: &Address,
) -> (BytesN<32>, Address, FillReceipt) {
    let taker = Address::generate(e);
    let token_in = fund(e, &taker, amount_in);
    let token_out = BytesN::from_array(e, &[9u8; 32]);
    let recipient = BytesN::from_array(e, &[7u8; 32]);
    let deadline = e.ledger().timestamp() + 3_600;

    let id = client.create_order(
        &taker,
        &token_in,
        &amount_in,
        &token_out,
        &(amount_in - 10),
        &recipient,
        &dest_chain,
        &deadline,
        &1u64,
    );

    let receipt = FillReceipt {
        order_id: id.clone(),
        solver: BytesN::from_array(e, &[3u8; 32]),
        repayment_address: repayment.clone(),
        origin_chain: STELLAR_CHAIN_ID,
        filled_at: 123,
    };
    (id, token_in, receipt)
}

#[test]
fn claim_releases_escrow_when_proven() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, oracle, _owner, fee_collector) = setup(&e);

    let repayment = Address::generate(&e);
    let dest_chain = 10u64;
    let (id, token_in, receipt) = open_order(&e, &client, 600, dest_chain, &repayment);
    let token = TokenClient::new(&e, &token_in);

    // The oracle proves the fill on the destination chain.
    let payload_hash = fill_receipt_hash(&e, &receipt);
    MockZkOracleClient::new(&e, &oracle).set_proven(&dest_chain, &payload_hash);

    client.claim(&receipt);

    // Fee = 600 * 30 / 10_000 = 1; the rest goes to the repayment address.
    assert_eq!(token.balance(&fee_collector), 1);
    assert_eq!(token.balance(&repayment), 599);
    assert_eq!(token.balance(&client.address), 0);

    // The order is now Claimed.
    let stored: Order = e.as_contract(&client.address, || {
        e.storage()
            .persistent()
            .get(&DataKey::Order(id.clone()))
            .unwrap()
    });
    assert_eq!(stored.status, OrderStatus::Claimed);
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")]
fn claim_without_proof_reverts() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, _oracle, _owner, _fc) = setup(&e);

    let repayment = Address::generate(&e);
    let (_id, _token_in, receipt) = open_order(&e, &client, 600, 10, &repayment);

    // No proof was recorded -> FillNotProven (error #8).
    client.claim(&receipt);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn claim_unknown_order_reverts() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, _oracle, _owner, _fc) = setup(&e);

    // A receipt whose order_id was never opened -> OrderNotFound (error #3).
    let receipt = FillReceipt {
        order_id: BytesN::from_array(&e, &[1u8; 32]),
        solver: BytesN::from_array(&e, &[3u8; 32]),
        repayment_address: Address::generate(&e),
        origin_chain: STELLAR_CHAIN_ID,
        filled_at: 123,
    };
    client.claim(&receipt);
}

#[test]
#[should_panic(expected = "Error(Contract, #9)")]
fn claim_rejects_wrong_origin_chain() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, _oracle, _owner, _fc) = setup(&e);

    let repayment = Address::generate(&e);
    let (_id, _token_in, mut receipt) = open_order(&e, &client, 600, 10, &repayment);

    // A fill that names a different origin chain -> OriginChainMismatch (error #9).
    receipt.origin_chain = STELLAR_CHAIN_ID + 1;
    client.claim(&receipt);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn claim_twice_reverts() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, oracle, _owner, _fc) = setup(&e);

    let repayment = Address::generate(&e);
    let dest_chain = 10u64;
    let (_id, _token_in, receipt) = open_order(&e, &client, 600, dest_chain, &repayment);

    let payload_hash = fill_receipt_hash(&e, &receipt);
    MockZkOracleClient::new(&e, &oracle).set_proven(&dest_chain, &payload_hash);

    client.claim(&receipt);
    // Order is no longer Open -> OrderInactive (error #4).
    client.claim(&receipt);
}
