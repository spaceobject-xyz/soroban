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
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype,
    panic_with_error, Address, Bytes, BytesN, Env,
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
    /// The ZK oracle has no proof recorded for this fill on the destination chain.
    FillNotProven = 8,
    /// The `fill_receipt` does not reference the order being claimed.
    FillReceiptMismatch = 9,
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
    /// [`ZkOracle`](ZkOracleInterface) consulted by [`SpaceObject::claim`] to
    /// confirm a fill was proven on the destination chain.
    pub zk_oracle: Address,
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

/// A destination-chain fill, as attested by the ZK oracle.
///
/// Mirrors the destination contract's `FillReceipt` (see the EVM `SpaceObject`),
/// plus the `order_id` it settles so the proof is bound to a specific order.
/// `claim` releases this chain's escrow to `repayment_address`, which is a
/// *this-chain* account (the origin chain is where the solver is repaid). The
/// keccak256 of its fixed-layout encoding (see [`fill_receipt_hash`]) is the
/// `payload_hash` the oracle proves; that layout is a cross-chain commitment the
/// prover/circuit must mirror byte-for-byte.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FillReceipt {
    /// Content id of the order this fill settles (binds the proof to the order).
    pub order_id: BytesN<32>,
    /// Destination-chain solver address, in raw 32-byte form.
    pub solver: BytesN<32>,
    /// This-chain account the escrow is released to (the solver's repayment).
    pub repayment_address: Address,
    /// Origin (this) chain id recorded at fill time on the destination chain.
    pub origin_chain: u32,
    /// Destination-chain ledger time the fill was recorded.
    pub filled_at: u64,
}

/// Emitted when a maker releases an order's escrow after proving the fill.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderClaimed {
    #[topic]
    pub order_id: BytesN<32>,
    #[topic]
    pub repayment_address: Address,
    pub token_in: Address,
    /// Amount released to `repayment_address` (escrow minus `fee`).
    pub amount: i128,
    /// Protocol fee taken from the escrow and sent to the fee collector.
    pub fee: i128,
}

/// The subset of the [`ZkOracle`](../zk_oracle) interface `claim` depends on.
///
/// Declaring the interface here generates a [`ZkOracleClient`] for the
/// cross-contract call without importing the oracle's WASM.
#[contractclient(name = "ZkOracleClient")]
pub trait ZkOracleInterface {
    /// Whether a proof has been recorded for `(chain_id, payload_hash)`.
    fn is_proven(e: Env, chain_id: u64, payload_hash: BytesN<32>) -> bool;
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

    /// Releases an order's escrow once its destination-chain fill has been proven.
    ///
    /// Looks up the `Open` order for `order_id`, hashes `fill_receipt` to the
    /// `payload_hash` the ZK oracle proves (see [`fill_receipt_hash`]), and asks
    /// the configured [`ZkOracle`](ZkOracleInterface) whether
    /// `(order.dest_chain, payload_hash)` has been proven. On `true` it takes the
    /// protocol fee, sends the remainder to `fill_receipt.repayment_address`,
    /// marks the order [`OrderStatus::Claimed`], and emits [`OrderClaimed`].
    ///
    /// Permissionless: the proof is the authorization, and the payout target is
    /// fixed by the proven `payload_hash`, so the caller cannot redirect funds.
    /// The `Open` → `Claimed` transition makes it single-use (replay protection).
    #[when_not_paused]
    pub fn claim(e: &Env, order_id: BytesN<32>, fill_receipt: FillReceipt) {
        // The receipt must be for the order being claimed.
        if fill_receipt.order_id != order_id {
            panic_with_error!(e, Error::FillReceiptMismatch);
        }

        // The order must exist and still be awaiting a fill.
        let mut order: Order = e
            .storage()
            .persistent()
            .get(&DataKey::Order(order_id.clone()))
            .unwrap_or_else(|| panic_with_error!(e, Error::OrderNotFound));
        if order.status != OrderStatus::Open {
            panic_with_error!(e, Error::OrderInactive);
        }

        // The oracle must hold a proof that this exact fill happened on the
        // order's destination chain.
        let config = Self::get_config(e);
        let payload_hash = fill_receipt_hash(e, &fill_receipt);
        let oracle = ZkOracleClient::new(e, &config.zk_oracle);
        if !oracle.is_proven(&order.dest_chain, &payload_hash) {
            panic_with_error!(e, Error::FillNotProven);
        }

        // Effects: close the order before moving funds (CEI / no double claim).
        order.status = OrderStatus::Claimed;
        e.storage()
            .persistent()
            .set(&DataKey::Order(order_id.clone()), &order);
        e.storage().persistent().extend_ttl(
            &DataKey::Order(order_id.clone()),
            ORDER_TTL_THRESHOLD,
            ORDER_TTL_EXTEND,
        );
        e.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND);

        // Interactions: split the escrow between the fee collector and the solver.
        // `amount_in > 0` and `fee_bps <= MAX_FEE_BPS` (both enforced on write),
        // so `0 <= fee <= amount_in`; the multiply is range-checked for safety.
        let fee = order
            .amount_in
            .checked_mul(config.fee_bps as i128)
            .expect("fee overflow")
            / MAX_FEE_BPS as i128;
        let net = order.amount_in - fee;

        let token = TokenClient::new(e, &order.token_in);
        let contract = e.current_contract_address();
        if fee > 0 {
            token.transfer(&contract, &config.fee_collector, &fee);
        }
        if net > 0 {
            token.transfer(&contract, &fill_receipt.repayment_address, &net);
        }

        OrderClaimed {
            order_id,
            repayment_address: fill_receipt.repayment_address,
            token_in: order.token_in,
            amount: net,
            fee,
        }
        .publish(e);
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

/// `payload_hash` of a [`FillReceipt`]: `keccak256` over a fixed-layout preimage.
///
/// The preimage is the concatenation, in order, of:
/// `order_id:32 ‖ solver:32 ‖ repayment_address.xdr ‖ origin_chain:be4 ‖
/// filled_at:be8`. This is the value the ZK oracle proves as its second public
/// signal, so the prover/circuit must build the identical preimage byte-for-byte.
fn fill_receipt_hash(e: &Env, r: &FillReceipt) -> BytesN<32> {
    let mut buf = Bytes::new(e);
    buf.extend_from_array(&r.order_id.to_array());
    buf.extend_from_array(&r.solver.to_array());
    buf.append(&r.repayment_address.clone().to_xdr(e));
    buf.extend_from_array(&r.origin_chain.to_be_bytes());
    buf.extend_from_array(&r.filled_at.to_be_bytes());
    e.crypto().keccak256(&buf).to_bytes()
}

mod test;
