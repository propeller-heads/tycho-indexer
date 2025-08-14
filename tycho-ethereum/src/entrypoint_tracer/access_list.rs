use std::{
    collections::{BTreeMap, HashMap, HashSet},
    str::FromStr,
};

use alloy::{
    hex,
    rpc::client::{ClientBuilder, RpcClient},
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use tycho_common::{
    models::{
        blockchain::{AccountOverrides, RPCTracerParams, StorageOverride},
        Address, BlockHash,
    },
    serde_primitives::hex_bytes_vec,
    Bytes,
};

use crate::RPCError;


fn build_state_overrides(overrides: &BTreeMap<Address, AccountOverrides>) -> Map<String, Value> {
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

#[derive(Debug, Deserialize)]
pub struct AccessListResult {
    #[serde(rename = "accessList")]
    pub access_list: Vec<AccessListEntry>,
    #[serde(rename = "gasUsed")]
    pub gas_used: String,
}

#[derive(Debug, Deserialize)]
pub struct AccessListEntry {
    pub address: String,
    #[serde(rename = "storageKeys")]
    #[serde(with = "hex_bytes_vec")]
    pub storage_keys: Vec<Vec<u8>>,
}

pub(crate) struct AccessListTracer {
    client: RpcClient,
}

impl AccessListTracer {
    pub fn new(node_url: &str) -> Result<Self, RPCError> {
        let url = url::Url::parse(node_url)
            .map_err(|_| RPCError::SetupError("Invalid URL".to_string()))?;
        Ok(Self { client: ClientBuilder::default().http(url) })
    }
}

impl AccessListResult {
    pub fn accessed_slots(&self) -> HashMap<Address, HashSet<Bytes>> {
        let mut out = HashMap::new();

        for entry in &self.access_list {
            // Parse Address
            let addr = entry
                .address
                .strip_prefix("0x")
                .unwrap_or(&entry.address);
            let addr = Address::from_str(&addr).unwrap(); //TODO: remove unwrap

            // Parse storage keys
            let set = entry
                .storage_keys
                .iter()
                .cloned()
                .map(Into::into)
                .collect();

            out.insert(addr, set);
        }
        out
    }
}

impl AccessListTracer {
    pub async fn get_access_list(
        &self,
        block_hash: &BlockHash,
        target: &Address,
        params: &RPCTracerParams,
    ) -> Result<HashMap<Address, HashSet<Bytes>>, RPCError> {
        let state_overrides = build_state_overrides(
            &params
                .state_overrides
                .as_ref()
                .unwrap_or(&BTreeMap::new()),
        );

        let mut tx_params = json!({
            "to": target.to_string(),
            "data": params.calldata.to_string()
        });

        if let Some(caller) = &params.caller {
            tx_params["from"] = json!(caller.to_string());
        }

        let rpc_params = if state_overrides.is_empty() {
            json!([tx_params, block_hash.to_string()])
        } else {
            json!([tx_params, block_hash.to_string(), Value::Object(state_overrides)])
        };

        let res: AccessListResult = self
            .client
            .request("eth_createAccessList", rpc_params)
            .await
            .map_err(|e| {
                RPCError::UnknownError(format!("eth_createAccessList call failed: {e}"))
            })?;

        Ok(res.accessed_slots())
    }
}

mod tests {
    use std::{collections::BTreeMap, env};

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
