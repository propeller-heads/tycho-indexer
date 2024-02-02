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

pub trait EventHandlers {
    // Get all relevent changed attributes from the event
    fn get_changed_attributes(
        &self,
        storage_changes: &[StorageChange],
        pool: &Pool,
    ) -> Vec<Attribute>;

    // Get all relevent balance deltas from the event
    fn get_balance_delta(&self, pool: &Pool, ordinal: u64) -> Vec<BalanceDelta>;
}

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
    fn get_changed_attributes(
        &self,
        storage_changes: &[StorageChange],
        pool: &Pool,
    ) -> Vec<Attribute> {
        match self {
            EventType::Initialize(e) => e.get_changed_attributes(storage_changes, pool),
            EventType::Swap(e) => e.get_changed_attributes(storage_changes, pool),
            EventType::Flash(e) => e.get_changed_attributes(storage_changes, pool),
            EventType::Mint(e) => e.get_changed_attributes(storage_changes, pool),
            EventType::Burn(e) => e.get_changed_attributes(storage_changes, pool),
            EventType::Collect(e) => e.get_changed_attributes(storage_changes, pool),
            EventType::SetFeeProtocol(e) => e.get_changed_attributes(storage_changes, pool),
            EventType::CollectProtocol(e) => e.get_changed_attributes(storage_changes, pool),
        }
    }

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

pub fn get_log_changed_attributes(
    event: &Log,
    storage_changes: &[StorageChange],
    pool: &Pool,
) -> Vec<Attribute> {
    if let Some(event) = decode_event(event) {
        return event.get_changed_attributes(storage_changes, pool);
    };

    // If no event is matched, return empty
    vec![]
}

pub fn get_log_changed_balances(event: &Log, pool: &Pool) -> Vec<BalanceDelta> {
    if let Some(e) = decode_event(event) {
        return e.get_balance_delta(pool, event.ordinal);
    };

    // If no event is matched, return empty
    vec![]
}
