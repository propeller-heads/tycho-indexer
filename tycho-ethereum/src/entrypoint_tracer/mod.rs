use std::{
    collections::{BTreeMap, HashMap, HashSet},
    str::FromStr,
};

use serde::Deserialize;
use serde_json::{json, Map, Value};
use tycho_common::{
    models::{
        blockchain::{AccountOverrides, StorageOverride},
        Address,
    },
    serde_primitives::hex_bytes_vec,
    Bytes,
};

use crate::RPCError;

#[cfg(feature = "onchain_data")]
pub mod balance_slot_detector;
pub mod tracer;

#[derive(Debug, Deserialize)]
pub struct AccessListResult {
    #[serde(rename = "accessList")]
    pub access_list: Vec<AccessListEntry>,
    #[serde(rename = "gasUsed")]
    pub gas_used: String,
    #[serde(rename = "error")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AccessListEntry {
    pub address: String,
    #[serde(rename = "storageKeys")]
    #[serde(with = "hex_bytes_vec")]
    pub storage_keys: Vec<Vec<u8>>,
}

pub fn build_state_overrides(
    overrides: &BTreeMap<Address, AccountOverrides>,
) -> Map<String, Value> {
    let mut state_overrides = Map::new();

    for (address, account_override) in overrides {
        let mut override_obj = Map::new();

        if let Some(ref code) = account_override.code {
            override_obj.insert("code".to_string(), json!(code));
        }

        if let Some(ref balance) = account_override.native_balance {
            override_obj.insert("balance".to_string(), json!(balance.to_string()));
        }

        if let Some(ref slots) = account_override.slots {
            match slots {
                StorageOverride::Diff(slot_map) => {
                    let mut state_diff = Map::new();
                    for (slot, value) in slot_map {
                        state_diff.insert(slot.to_string(), json!(value));
                    }
                    override_obj.insert("stateDiff".to_string(), json!(state_diff));
                }
                StorageOverride::Replace(slot_map) => {
                    let mut state_map = Map::new();
                    for (slot, value) in slot_map {
                        state_map.insert(slot.to_string(), json!(value));
                    }
                    override_obj.insert("state".to_string(), json!(state_map));
                }
            }
        }

        if !override_obj.is_empty() {
            state_overrides.insert(address.to_string(), json!(override_obj));
        }
    }

    state_overrides
}

impl AccessListResult {
    pub fn try_get_accessed_slots(&self) -> Result<HashMap<Address, HashSet<Bytes>>, RPCError> {
        if let Some(error) = &self.error {
            return Err(RPCError::TracingFailure(error.to_string()));
        }

        let mut out = HashMap::new();

        for entry in &self.access_list {
            // Parse Address
            let addr = entry
                .address
                .strip_prefix("0x")
                .unwrap_or(&entry.address);
            let addr =
                Address::from_str(addr).map_err(|e| RPCError::UnknownError(e.to_string()))?;

            // Parse storage keys
            let set = entry
                .storage_keys
                .iter()
                .cloned()
                .map(Into::into)
                .collect();

            out.insert(addr, set);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, str::FromStr};

    use tycho_common::models::blockchain::{AccountOverrides, StorageOverride};

    use super::*;

    #[test]
    fn test_build_state_overrides() {
        let mut state_overrides = BTreeMap::new();
        let mut slots = BTreeMap::new();

        slots.insert(
            Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
            Bytes::from_str("0x0000000000000000000000000000000000000000000000000000000000000042")
                .unwrap(),
        );

        let account_override = AccountOverrides {
            slots: Some(StorageOverride::Diff(slots)),
            native_balance: None,
            code: Some(Bytes::from_str("0x6060604052").unwrap()),
        };

        state_overrides.insert(
            Bytes::from_str("0x1234567890123456789012345678901234567890").unwrap(),
            account_override,
        );

        let result = build_state_overrides(&state_overrides);

        assert!(!result.is_empty());
        assert!(result.contains_key("0x1234567890123456789012345678901234567890"));

        let override_obj = &result["0x1234567890123456789012345678901234567890"];
        assert!(override_obj.get("code").is_some());
        assert!(override_obj.get("stateDiff").is_some());
    }
}
