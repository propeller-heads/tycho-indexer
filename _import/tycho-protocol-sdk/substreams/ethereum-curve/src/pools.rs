use std::collections::HashMap;

use crate::abi::pool;
use anyhow::{self, Context, Result};
use ethabi::token;
use serde::Deserialize;
use serde_qs;
use substreams_ethereum::{
    block_view::LogView,
    pb::{eth, eth::v2::Block},
};
use tycho_substreams::prelude::*;

const PARAMS_SEPERATOR: &str = ",";

#[derive(Debug, Deserialize)]
struct PoolQueryParams {
    address: String,
    tx_hash: String,
    tokens: Vec<String>,
    attributes: Vec<(String, String)>,
}

pub fn emit_specific_pools(
    params: &String,
    block: &eth::v2::Block,
) -> Result<Vec<ProtocolComponent>> {
    let pools: HashMap<String, PoolQueryParams> = params
        .split(PARAMS_SEPERATOR)
        .map(|param| {
            // TODO UNSAFE
            let pool: PoolQueryParams = serde_qs::from_str(&param).unwrap();
            (pool.tx_hash.clone(), pool)
        })
        .collect::<HashMap<_, _>>();

    let mut components: Vec<ProtocolComponent> = vec![];

    for tx in block.transactions() {
        let encoded_hash = hex::encode(tx.hash.clone());
        if let Some(pool) = pools.get(&encoded_hash) {
            let component = ProtocolComponent {
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
                    .with_context(|| "")?,
                static_att: pool
                    .attributes
                    .clone()
                    .into_iter()
                    .map(|attr| Attribute {
                        name: attr.0,
                        value: attr.1.into(),
                        change: ChangeType::Creation.into(),
                    })
                    .collect::<Vec<_>>(),
                contracts: vec![hex::decode(pool.address.clone()).with_context(|| "")?],
                change: ChangeType::Creation.into(),
                protocol_type: Some(ProtocolType {
                    name: "curve_pool".into(),
                    financial_type: FinancialType::Swap.into(),
                    attribute_schema: Vec::new(),
                    implementation_type: ImplementationType::Vm.into(),
                }),
            };
            components.push(component);
        }
    }
    Ok(components)
}
