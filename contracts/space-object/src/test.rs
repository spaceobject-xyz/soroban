#![cfg(test)]

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::token::{StellarAssetClient, TokenClient};
use soroban_sdk::{BytesN, Env};

fn setup(e: &Env) -> (SpaceObjectClient<'static>, Address, Address) {
    let owner = Address::generate(e);
    let fee_collector = Address::generate(e);
    let config = ProtocolConfig {
        fee_bps: 30,
        fee_collector: fee_collector.clone(),
    };
    let id = e.register(SpaceObject, (owner.clone(), config));
    (SpaceObjectClient::new(e, &id), owner, fee_collector)
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
    let (client, owner, fee_collector) = setup(&e);

    assert_eq!(client.get_owner(), Some(owner));
    let config = client.get_config();
    assert_eq!(config.fee_bps, 30);
    assert_eq!(config.fee_collector, fee_collector);
}

#[test]
fn owner_can_update_config() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, _owner, fee_collector) = setup(&e);

    client.set_config(&ProtocolConfig {
        fee_bps: 50,
        fee_collector,
    });

    assert_eq!(client.get_config().fee_bps, 50);
}

#[test]
#[should_panic]
fn set_config_rejects_excessive_fee() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, _owner, fee_collector) = setup(&e);

    client.set_config(&ProtocolConfig {
        fee_bps: MAX_FEE_BPS + 1,
        fee_collector,
    });
}

#[test]
fn owner_can_pause_and_unpause() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, owner, _fc) = setup(&e);

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
    let (client, _owner, _fc) = setup(&e);

    let taker = Address::generate(&e);
    let token_in = fund(&e, &taker, 1_000);
    let token_client = TokenClient::new(&e, &token_in);

    let token_out = BytesN::from_array(&e, &[9u8; 32]);
    let recipient = BytesN::from_array(&e, &[7u8; 32]);
    let deadline = e.ledger().timestamp() + 3_600;

    let id = client.create_order(
        &taker, &token_in, &600i128, &token_out, &590i128, &recipient, &10u32, &deadline, &1u64,
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
    let (client, _owner, _fc) = setup(&e);

    let taker = Address::generate(&e);
    let token_in = fund(&e, &taker, 2_000);
    let token_out = BytesN::from_array(&e, &[9u8; 32]);
    let recipient = BytesN::from_array(&e, &[7u8; 32]);
    let deadline = e.ledger().timestamp() + 3_600;

    let id1 = client.create_order(
        &taker, &token_in, &600i128, &token_out, &590i128, &recipient, &10u32, &deadline, &1u64,
    );
    let id2 = client.create_order(
        &taker, &token_in, &600i128, &token_out, &590i128, &recipient, &10u32, &deadline, &2u64,
    );

    assert_ne!(id1, id2);
}

#[test]
#[should_panic]
fn duplicate_order_rejected() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, _owner, _fc) = setup(&e);

    let taker = Address::generate(&e);
    let token_in = fund(&e, &taker, 2_000);
    let token_out = BytesN::from_array(&e, &[9u8; 32]);
    let recipient = BytesN::from_array(&e, &[7u8; 32]);
    let deadline = e.ledger().timestamp() + 3_600;

    // Identical terms + nonce hash to the same id -> the second call is rejected.
    client.create_order(
        &taker, &token_in, &600i128, &token_out, &590i128, &recipient, &10u32, &deadline, &1u64,
    );
    client.create_order(
        &taker, &token_in, &600i128, &token_out, &590i128, &recipient, &10u32, &deadline, &1u64,
    );
}

#[test]
#[should_panic]
fn create_order_rejects_zero_amount() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, _owner, _fc) = setup(&e);

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
        &10u32,
        &(e.ledger().timestamp() + 3_600),
        &1u64,
    );
}

#[test]
#[should_panic]
fn create_order_rejects_past_deadline() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, _owner, _fc) = setup(&e);

    let taker = Address::generate(&e);
    let token_in = fund(&e, &taker, 1_000);
    let token_out = BytesN::from_array(&e, &[0u8; 32]);
    let recipient = BytesN::from_array(&e, &[0u8; 32]);

    e.ledger().set_timestamp(1_000);
    client.create_order(
        &taker, &token_in, &600i128, &token_out, &590i128, &recipient, &10u32, &500u64, &1u64,
    );
}

#[test]
#[should_panic]
fn create_order_blocked_when_paused() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, owner, _fc) = setup(&e);

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
        &10u32,
        &(e.ledger().timestamp() + 3_600),
        &1u64,
    );
}
