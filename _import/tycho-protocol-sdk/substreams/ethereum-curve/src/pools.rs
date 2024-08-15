use anyhow::{Context, Result};
use serde::Deserialize;
use std::{collections::HashMap, iter::zip};
use substreams_ethereum::pb::eth::v2::TransactionTrace;
use tycho_substreams::prelude::*;

const PARAMS_SEPERATOR: &str = ",";

#[derive(Debug, Deserialize, PartialEq)]
struct PoolQueryParams {
    address: String,
    contracts: Option<Vec<String>>,
    tx_hash: String,
    tokens: Vec<String>,
    static_attribute_keys: Option<Vec<String>>,
    static_attribute_vals: Option<Vec<String>>,
    attribute_keys: Option<Vec<String>>,
    attribute_vals: Option<Vec<String>>,
}

/// This function parses the `params` string and extracts the pool query parameters. `params` are
///  comma-separated, URL-encoded (defined by `serde-qs`) strings, with each component defining the
///  pool query parameters defined in the struct above. We then iterate through the transactions in
///  a block, and then if the transaction hash matches our parameter, we emit a `ProtocolComponent`
///  defined by the metadata from above alongside some basic defaults that we know for Curve.
///
/// Static attributes are defined as a vector of tuples with the name and value of the attribute.
///  These contain things like the pool type, specific pool fees, etc. You can see
///  `pool_factories.rs` for an example of the modern curve pool attributes and also the ones chosen
///  for 3pool, etc.
///
/// This function can error based on some basic parsing errors and deeper down hex decoding errors
///  if various addresses are not formatted properly.
pub fn emit_specific_pools(
    params: &str,
    tx: &TransactionTrace,
) -> Result<Option<(ProtocolComponent, Vec<EntityChanges>)>> {
    let pools = parse_params(params)?;
    create_component(tx, pools)
}

fn create_component(
    tx: &TransactionTrace,
    pools: HashMap<String, PoolQueryParams>,
) -> Result<Option<(ProtocolComponent, Vec<EntityChanges>)>> {
    let encoded_hash = hex::encode(tx.hash.clone());
    if let Some(pool) = pools.get(&encoded_hash) {
        Ok(Some((
            ProtocolComponent {
                id: pool.address.clone(),
                tx: Some(Transaction {
                    to: tx.to.clone(),
                    from: tx.from.clone(),
                    hash: tx.hash.clone(),
                    index: tx.index.into(),
                }),
                tokens: pool
                    .tokens
                    .clone()
                    .into_iter()
                    .map(|token| Result::Ok(hex::decode(token)?))
                    .collect::<Result<Vec<_>>>()
                    .with_context(|| "Token addresses were not formatted properly")?,
                static_att: zip(
                    pool.static_attribute_keys
                        .clone()
                        .unwrap_or(vec![]),
                    pool.static_attribute_vals
                        .clone()
                        .unwrap_or(vec![]),
                )
                .clone()
                .map(|(key, value)| Attribute {
                    name: key,
                    value: value.into(),
                    change: ChangeType::Creation.into(),
                })
                .collect::<Vec<_>>(),
                contracts: pool
                    .contracts
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|contract| {
                        hex::decode(contract)
                            .with_context(|| "Pool contracts was not formatted properly")
                    })
                    .chain(std::iter::once(
                        hex::decode(&pool.address)
                            .with_context(|| "Pool address was not formatted properly"),
                    ))
                    .collect::<Result<Vec<Vec<u8>>>>()?,
                change: ChangeType::Creation.into(),
                protocol_type: Some(ProtocolType {
                    name: "curve_pool".into(),
                    financial_type: FinancialType::Swap.into(),
                    attribute_schema: Vec::new(),
                    implementation_type: ImplementationType::Vm.into(),
                }),
            },
            vec![EntityChanges {
                component_id: format!("0x{}", pool.address.clone()),
                attributes: zip(
                    pool.attribute_keys
                        .clone()
                        .unwrap_or(vec![]),
                    pool.attribute_vals
                        .clone()
                        .unwrap_or(vec![]),
                )
                .clone()
                .map(|(key, value)| Attribute {
                    name: key,
                    value: value.into(),
                    change: ChangeType::Creation.into(),
                })
                .collect::<Vec<_>>(),
            }],
        )))
    } else {
        Ok(None)
    }
}

fn parse_params(params: &str) -> Result<HashMap<String, PoolQueryParams>, anyhow::Error> {
    let pools: HashMap<String, PoolQueryParams> = params
        .split(PARAMS_SEPERATOR)
        .map(|param| {
            let pool: PoolQueryParams = serde_qs::from_str(param)
                .with_context(|| format!("Failed to parse pool query params: {0}", param))?;
            Ok((pool.tx_hash.clone(), pool))
        })
        .collect::<Result<HashMap<_, _>>>()
        .with_context(|| "Failed to parse all pool query params")?;
    Ok(pools)
}

mod tests {
    #[test]
    fn test_parse_params() {
        use crate::pools::{parse_params, PoolQueryParams};
        use std::collections::HashMap;
        // Existing test case
        let params = "address=0x5F890841f657d90E081bAbdB532A05996Af79Fe6&tx_hash=0xb71a66c1d93c525a2dd19a8db0da19e65be04f36e733af7f03e3c9dff41aa16a&tokens[]=0x6b175474e89094c44da98b954eedeac495271d0f&tokens[]=0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48&tokens[]=0xdac17f958d2ee523a2206206994597c13d831ec7&attribute_keys[]=key1&attribute_vals[]=val1".to_string();
        let expected_result = {
            let mut map = HashMap::new();
            map.insert(
                "0xb71a66c1d93c525a2dd19a8db0da19e65be04f36e733af7f03e3c9dff41aa16a".to_string(),
                PoolQueryParams {
                    address: "0x5F890841f657d90E081bAbdB532A05996Af79Fe6".to_string(),
                    contracts: None,
                    tx_hash: "0xb71a66c1d93c525a2dd19a8db0da19e65be04f36e733af7f03e3c9dff41aa16a"
                        .to_string(),
                    tokens: vec![
                        "0x6b175474e89094c44da98b954eedeac495271d0f".to_string(),
                        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string(),
                        "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string(),
                    ],
                    static_attribute_keys: None,
                    static_attribute_vals: None,
                    attribute_keys: Some(vec!["key1".to_string()]),
                    attribute_vals: Some(vec!["val1".to_string()]),
                },
            );
            map
        };
        assert_eq!(parse_params(&params).unwrap(), expected_result);
    }
}
