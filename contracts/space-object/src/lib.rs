#![no_std]

//! Source-chain escrow for a cross-chain intent bridge.
//!
//! A taker locks funds on this (source) chain via [`SpaceObject::create_order`].
//! A maker that fills the intent on the destination chain later releases the
//! escrow via [`SpaceObject::claim`]. The contract is [`Pausable`] (owner-gated
//! emergency stop) and [`Ownable`], and it holds an owner-governed
//! [`ProtocolConfig`] for protocol fees.

use soroban_sdk::token::TokenClient;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, Address,
    Bytes, BytesN, Env,
};
use stellar_access::ownable::{get_owner, set_owner, Ownable};
use stellar_contract_utils::pausable::{self as pausable, Pausable};
use stellar_macros::{only_owner, when_not_paused};

/// Upper bound for the protocol fee, in basis points (100% = 10_000 bps).
const MAX_FEE_BPS: u32 = 10_000;

/// Ledgers per day at the ~5s close rate, for storage TTL bookkeeping.
const DAY_IN_LEDGERS: u32 = 17_280;
/// How far to bump instance storage (config) on each write.
const INSTANCE_TTL_EXTEND: u32 = 7 * DAY_IN_LEDGERS;
const INSTANCE_TTL_THRESHOLD: u32 = INSTANCE_TTL_EXTEND - DAY_IN_LEDGERS;
/// How far to bump a persisted order's TTL when it is created.
const ORDER_TTL_EXTEND: u32 = 30 * DAY_IN_LEDGERS;
const ORDER_TTL_THRESHOLD: u32 = ORDER_TTL_EXTEND - DAY_IN_LEDGERS;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// A configured `fee_bps` exceeded [`MAX_FEE_BPS`].
    InvalidFee = 1,
    /// The caller is not the contract owner.
    Unauthorized = 2,
    /// No order exists for the supplied id.
    OrderNotFound = 3,
    /// The order is not in a state that allows the requested action.
    OrderInactive = 4,
    /// `amount_in` or `amount_out` was not a positive value.
    InvalidAmount = 5,
    /// `deadline` is not in the future.
    InvalidDeadline = 6,
    /// An order with this content id already exists (duplicate/replay).
    OrderExists = 7,
}

/// Lifecycle of an escrowed order on the source chain.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderStatus {
    /// Funds are escrowed and awaiting a maker fill.
    Open,
    /// A maker released the escrow after proving destination-chain delivery.
    Claimed,
    /// The taker reclaimed the escrow after expiry.
    Refunded,
}

/// Owner-governed protocol configuration.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolConfig {
    /// Protocol fee charged on a filled order, in basis points (1 = 0.01%).
    pub fee_bps: u32,
    /// Account that accrues protocol fees.
    pub fee_collector: Address,
}

/// A cross-chain swap intent whose source-chain funds are escrowed here.
///
/// In market-structure terms the `taker` is the user who locks funds on this
/// (source) chain; a maker later fills the intent on the destination chain and
/// releases this escrow. The order is content-addressed: its id is
/// `keccak256` over its terms (see [`order_id`]), so `id` is the storage key
/// rather than a stored field.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Order {
    /// User who escrowed the source-chain funds.
    pub taker: Address,
    /// Escrowed source-chain asset.
    pub token_in: Address,
    /// Amount of `token_in` escrowed; the protocol fee is taken from this on claim.
    pub amount_in: i128,
    /// Requested destination-chain asset, in raw 32-byte form.
    pub token_out: BytesN<32>,
    /// Requested amount of `token_out` on the destination chain.
    pub amount_out: i128,
    /// Recipient on the destination chain, in raw 32-byte form.
    pub recipient: BytesN<32>,
    /// Destination chain identifier.
    pub dest_chain: u64,
    /// Ledger timestamp after which the taker may refund the escrow.
    pub deadline: u64,
    /// Caller-supplied salt that makes otherwise-identical orders unique.
    pub nonce: u64,
    pub status: OrderStatus,
}

/// Emitted when a taker opens a new escrowed order.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderCreated {
    #[topic]
    pub order_id: BytesN<32>,
    #[topic]
    pub taker: Address,
    pub token_in: Address,
    pub amount_in: i128,
    pub token_out: BytesN<32>,
    pub amount_out: i128,
    pub recipient: BytesN<32>,
    pub dest_chain: u64,
    pub deadline: u64,
    pub nonce: u64,
}

#[contracttype]
enum DataKey {
    /// The [`ProtocolConfig`].
    Config,
    /// An escrowed [`Order`] by its content id.
    Order(BytesN<32>),
}

#[contract]
pub struct SpaceObject;

#[contractimpl]
impl SpaceObject {
    /// Initializes the escrow with its `owner` and starting protocol `config`.
    pub fn __constructor(e: &Env, owner: Address, config: ProtocolConfig) {
        if config.fee_bps > MAX_FEE_BPS {
            panic_with_error!(e, Error::InvalidFee);
        }
        set_owner(e, &owner);
        e.storage().instance().set(&DataKey::Config, &config);
    }

    /// Returns the current protocol configuration.
    pub fn get_config(e: &Env) -> ProtocolConfig {
        e.storage()
            .instance()
            .get(&DataKey::Config)
            .expect("config should be set")
    }

    /// Replaces the protocol configuration. Owner-only.
    #[only_owner]
    pub fn set_config(e: &Env, config: ProtocolConfig) {
        if config.fee_bps > MAX_FEE_BPS {
            panic_with_error!(e, Error::InvalidFee);
        }
        e.storage().instance().set(&DataKey::Config, &config);
    }

    // ---- Core escrow flow ----

    /// Escrows a taker's source-chain funds and opens a new cross-chain order.
    ///
    /// Pulls `amount_in` of `token_in` from `taker` into the contract, persists
    /// the resulting [`Order`] as [`OrderStatus::Open`], and emits `OrderCreated`.
    /// Requires the taker's authorization. Returns the order's content id
    /// (`keccak256` of its terms — see [`order_id`]). `nonce` makes otherwise
    /// identical orders unique; reusing one for the same terms is rejected.
    #[when_not_paused]
    pub fn create_order(
        e: &Env,
        taker: Address,
        token_in: Address,
        amount_in: i128,
        token_out: BytesN<32>,
        amount_out: i128,
        recipient: BytesN<32>,
        dest_chain: u64,
        deadline: u64,
        nonce: u64,
    ) -> BytesN<32> {
        // The taker authorizes these exact order terms.
        taker.require_auth();

        if amount_in <= 0 || amount_out <= 0 {
            panic_with_error!(e, Error::InvalidAmount);
        }
        if deadline <= e.ledger().timestamp() {
            panic_with_error!(e, Error::InvalidDeadline);
        }

        let order = Order {
            taker,
            token_in,
            amount_in,
            token_out,
            amount_out,
            recipient,
            dest_chain,
            deadline,
            nonce,
            status: OrderStatus::Open,
        };
        let id = order_id(e, &order);

        // Content-addressed ids must be unique: reject duplicates/replays.
        if e.storage().persistent().has(&DataKey::Order(id.clone())) {
            panic_with_error!(e, Error::OrderExists);
        }

        // Escrow: move the funds from the taker into this contract.
        TokenClient::new(e, &order.token_in).transfer(
            &order.taker,
            &e.current_contract_address(),
            &order.amount_in,
        );

        e.storage()
            .persistent()
            .set(&DataKey::Order(id.clone()), &order);
        e.storage().persistent().extend_ttl(
            &DataKey::Order(id.clone()),
            ORDER_TTL_THRESHOLD,
            ORDER_TTL_EXTEND,
        );
        e.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND);

        OrderCreated {
            order_id: id.clone(),
            taker: order.taker,
            token_in: order.token_in,
            amount_in: order.amount_in,
            token_out: order.token_out,
            amount_out: order.amount_out,
            recipient: order.recipient,
            dest_chain: order.dest_chain,
            deadline: order.deadline,
            nonce: order.nonce,
        }
        .publish(e);

        id
    }

    /// Releases an order's escrow to the `fill_receipt.repayment_address` that filled it on the
    /// destination chain.
    ///
    /// TODO: verify `fill_receipt` against the order, take the protocol fee,
    /// transfer the remainder to `fill_receipt.repayment_address`, mark the order [`OrderStatus::Claimed`],
    /// and emit `Claimed`.
    #[when_not_paused]
    pub fn claim(e: &Env, order_id: BytesN<32>, fill_receipt: Bytes) {
        let _ = (order_id, fill_receipt);
        unimplemented!()
    }
}

//
// ---- Extensions ----
//

#[contractimpl(contracttrait)]
impl Ownable for SpaceObject {}

#[contractimpl]
impl Pausable for SpaceObject {
    fn paused(e: &Env) -> bool {
        pausable::paused(e)
    }

    fn pause(e: &Env, caller: Address) {
        require_owner(e, &caller);
        pausable::pause(e);
    }

    fn unpause(e: &Env, caller: Address) {
        require_owner(e, &caller);
        pausable::unpause(e);
    }
}

/// Authenticates `caller` and asserts it is the contract owner.
fn require_owner(e: &Env, caller: &Address) {
    caller.require_auth();
    let owner = get_owner(e).expect("owner should be set");
    if &owner != caller {
        panic_with_error!(e, Error::Unauthorized);
    }
}

/// Content id of an order: `keccak256` over a fixed-layout preimage of its
/// terms (every field except `status`).
///
/// The preimage is the concatenation, in order, of:
/// `taker.xdr ‖ token_in.xdr ‖ amount_in:be16 ‖ token_out:32 ‖
/// amount_out:be16 ‖ recipient:32 ‖ dest_chain:be8 ‖ deadline:be8 ‖ nonce:be8`.
/// keccak256 is chosen so an EVM destination chain can recompute the same id
/// from the identical preimage bytes. This layout is a cross-chain commitment:
/// the counterpart contract must mirror it byte-for-byte.
fn order_id(e: &Env, o: &Order) -> BytesN<32> {
    let mut buf = Bytes::new(e);
    buf.append(&o.taker.clone().to_xdr(e));
    buf.append(&o.token_in.clone().to_xdr(e));
    buf.extend_from_array(&o.amount_in.to_be_bytes());
    buf.extend_from_array(&o.token_out.to_array());
    buf.extend_from_array(&o.amount_out.to_be_bytes());
    buf.extend_from_array(&o.recipient.to_array());
    buf.extend_from_array(&o.dest_chain.to_be_bytes());
    buf.extend_from_array(&o.deadline.to_be_bytes());
    buf.extend_from_array(&o.nonce.to_be_bytes());
    e.crypto().keccak256(&buf).to_bytes()
}

mod test;
