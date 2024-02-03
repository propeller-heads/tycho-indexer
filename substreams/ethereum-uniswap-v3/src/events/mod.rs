use substreams_ethereum::{
    pb::eth::v2::{Log, StorageChange},
    Event,
};

use crate::{
    abi::pool::events::{
        Burn, Collect, CollectProtocol, Flash, Initialize, Mint, SetFeeProtocol, Swap,
    },
    pb::tycho::evm::{
        uniswap::v3::{BalanceDelta, Pool},
        v1::Attribute,
    },
};

pub mod burn;
pub mod collect;
pub mod collect_fee_protocol;
pub mod flash;
pub mod initialize;
pub mod mint;
pub mod set_fee_protocol;
pub mod swap;

/// A trait for extracting changed attributes and balance from an event.
pub trait EventHandlers {
    /// Get all relevant changed attributes from the `[StorageChange]`.
    /// If an attribute is changed multiple times, only the last state will be returned.
    ///
    /// # Arguments
    ///
    /// * `storage_changes` - A slice of `StorageChange` that indicates the changes in storage.
    /// * `pool` - Reference to the `Pool`.
    ///
    /// # Returns
    ///
    /// A vector of `Attribute` that represents the changed attributes.
    fn get_changed_attributes(
        &self,
        storage_changes: &[StorageChange],
        pool_address: &[u8; 20],
    ) -> Vec<Attribute>;

    /// Get all balance deltas from the event.
    ///
    /// # Arguments
    ///
    /// * `pool` - Reference to the `Pool`.
    /// * `ordinal` - The ordinal number of the event. This is used by the balance store to sort the
    ///   balance deltas in the correct order.
    ///
    /// # Returns
    ///
    /// A vector of `BalanceDelta` that represents the balance deltas.
    fn get_balance_delta(&self, pool: &Pool, ordinal: u64) -> Vec<BalanceDelta>;
}

/// Represent every events of a UniswapV3 pool.
pub enum EventType {
    Initialize(Initialize),
    Swap(Swap),
    Flash(Flash),
    Mint(Mint),
    Burn(Burn),
    Collect(Collect),
    SetFeeProtocol(SetFeeProtocol),
    CollectProtocol(CollectProtocol),
}

impl EventType {
    /// Get all relevant changed attributes from the event.
    ///
    /// # Arguments
    ///
    /// * `storage_changes` - A slice of `StorageChange` that indicates the changes in storage.
    /// * `pool` - Reference to the `Pool` structure.
    ///
    /// # Returns
    ///
    /// A vector of `Attribute` that represents the changed attributes.
    fn get_changed_attributes(
        &self,
        storage_changes: &[StorageChange],
        pool_address: &[u8; 20],
    ) -> Vec<Attribute> {
        match self {
            EventType::Initialize(e) => e.get_changed_attributes(storage_changes, pool_address),
            EventType::Swap(e) => e.get_changed_attributes(storage_changes, pool_address),
            EventType::Flash(e) => e.get_changed_attributes(storage_changes, pool_address),
            EventType::Mint(e) => e.get_changed_attributes(storage_changes, pool_address),
            EventType::Burn(e) => e.get_changed_attributes(storage_changes, pool_address),
            EventType::Collect(e) => e.get_changed_attributes(storage_changes, pool_address),
            EventType::SetFeeProtocol(e) => e.get_changed_attributes(storage_changes, pool_address),
            EventType::CollectProtocol(e) => {
                e.get_changed_attributes(storage_changes, pool_address)
            }
        }
    }

    /// Get all relevant balance deltas from the event.
    ///
    /// # Arguments
    ///
    /// * `pool` - Reference to the `Pool` structure.
    /// * `ordinal` - The ordinal number representing the order of the event.
    ///
    /// # Returns
    ///
    /// A vector of `BalanceDelta` that represents the balance deltas.
    fn get_balance_delta(&self, pool: &Pool, ordinal: u64) -> Vec<BalanceDelta> {
        match self {
            EventType::Initialize(e) => e.get_balance_delta(pool, ordinal),
            EventType::Swap(e) => e.get_balance_delta(pool, ordinal),
            EventType::Flash(e) => e.get_balance_delta(pool, ordinal),
            EventType::Mint(e) => e.get_balance_delta(pool, ordinal),
            EventType::Burn(e) => e.get_balance_delta(pool, ordinal),
            EventType::Collect(e) => e.get_balance_delta(pool, ordinal),
            EventType::SetFeeProtocol(e) => e.get_balance_delta(pool, ordinal),
            EventType::CollectProtocol(e) => e.get_balance_delta(pool, ordinal),
        }
    }
}

/// Decodes a given log into an `EventType`.
///
/// # Arguments
///
/// * `event` - A reference to the `Log`.
///
/// # Returns
///
/// An `Option<EventType>` that represents the decoded event type.
pub fn decode_event(event: &Log) -> Option<EventType> {
    if let Some(e) = Swap::match_and_decode(event) {
        Some(EventType::Swap(e))
    } else if let Some(e) = Mint::match_and_decode(event) {
        Some(EventType::Mint(e))
    } else if let Some(e) = Burn::match_and_decode(event) {
        Some(EventType::Burn(e))
    } else if let Some(e) = Initialize::match_and_decode(event) {
        Some(EventType::Initialize(e))
    } else if let Some(e) = Flash::match_and_decode(event) {
        Some(EventType::Flash(e))
    } else if let Some(e) = Collect::match_and_decode(event) {
        Some(EventType::Collect(e))
    } else if let Some(e) = SetFeeProtocol::match_and_decode(event) {
        Some(EventType::SetFeeProtocol(e))
    } else {
        CollectProtocol::match_and_decode(event).map(EventType::CollectProtocol)
    }
}

/// Gets the changed attributes from the log.
///
/// # Arguments
///
/// * `event` - A reference to the `Log`.
/// * `storage_changes` - A slice of `StorageChange` that indicates the changes in storage.
/// * `pool` - Reference to the `Pool` structure.
///
/// # Returns
///
/// A vector of `Attribute` that represents the changed attributes.
pub fn get_log_changed_attributes(
    event: &Log,
    storage_changes: &[StorageChange],
    pool_address: &[u8; 20],
) -> Vec<Attribute> {
    if let Some(event) = decode_event(event) {
        return event.get_changed_attributes(storage_changes, pool_address);
    };

    // If no event is matched, return empty
    vec![]
}

/// Gets the changed balances from the log.
///
/// # Arguments
///
/// * `event` - A reference to the `Log`.
/// * `pool` - Reference to the `Pool` structure.
///
/// # Returns
///
/// A vector of `BalanceDelta` that represents
pub fn get_log_changed_balances(event: &Log, pool: &Pool) -> Vec<BalanceDelta> {
    if let Some(e) = decode_event(event) {
        return e.get_balance_delta(pool, event.ordinal);
    };

    // If no event is matched, return empty
    vec![]
}
