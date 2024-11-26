use tycho_core::keccak256;

use crate::protocol::vm::utils::SlotId;

pub mod account_storage;
pub mod engine_db;
pub mod simulation;
pub mod token;
pub mod traces;
pub mod tycho_models;

/// Enum representing the type of contract compiler.
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ContractCompiler {
    Solidity,
    Vyper,
}

impl ContractCompiler {
    /// Computes the storage slot for a given mapping based on the base storage slot of the map and
    /// the key.
    ///
    /// # Arguments
    ///
    /// * `map_base_slot` - A byte slice representing the base storage slot of the mapping.
    /// * `key` - A byte slice representing the key for which the storage slot is being computed.
    ///
    /// # Returns
    ///
    /// A `SlotId` representing the computed storage slot.
    ///
    /// # Notes
    ///
    /// - For `Solidity`, the slot is computed as `keccak256(key + map_base_slot)`.
    /// - For `Vyper`, the slot is computed as `keccak256(map_base_slot + key)`.
    pub fn compute_map_slot(&self, map_base_slot: &[u8], key: &[u8]) -> SlotId {
        let concatenated = match &self {
            ContractCompiler::Solidity => [key, map_base_slot].concat(),
            ContractCompiler::Vyper => [map_base_slot, key].concat(),
        };

        let slot_bytes = keccak256(&concatenated);

        SlotId::from_big_endian(&slot_bytes)
    }
}
