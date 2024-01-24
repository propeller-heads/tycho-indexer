use substreams::prelude::BigInt;
use substreams_ethereum::pb::eth::v2::{self as eth};
use substreams_helper::hex::Hexable;

use crate::pb::tycho::evm::{
    uniswap::v2::Pools,
    v1::{
        Attribute, ChangeType, FinancialType, ImplementationType, ProtocolComponent, ProtocolType,
        SameTypeTransactionChanges, TransactionEntityChanges,
    },
};
use crate::pb::tycho::evm::v1::Transaction;

#[substreams::handlers::map]
pub fn extract_protocol_components(
    block: eth::Block,
    pools_created: Pools,
) -> Result<SameTypeTransactionChanges, substreams::errors::Error> {
    let mut tx_entity_changes: Vec<TransactionEntityChanges> = vec![];

    handle_created_pools(block, pools_created, &mut tx_entity_changes);

    Ok(SameTypeTransactionChanges { changes: tx_entity_changes })
}

fn handle_created_pools(
    block: eth::Block,
    pools_created: Pools,
    tx_entity_changes: &mut Vec<TransactionEntityChanges>,
) {
    for pool in pools_created.pools {
        let tx = block
            .transaction_traces
            .iter()
            .find(|tx| tx.hash == pool.created_tx_hash)
            .expect("Transaction not found");

        let tycho_tx: Transaction = tx.into();

        tx_entity_changes.push(TransactionEntityChanges {
            tx: Option::from(tycho_tx),
            entity_changes: vec![],
            component_changes: vec![ProtocolComponent {
                id: pool.address.to_hex(),
                tokens: vec![pool.token0, pool.token1],
                contracts: vec![pool.address],
                static_att: vec![
                    // Trading Fee is hardcoded to 0.3%, saved as int in bps (basis points)
                    Attribute {
                        name: "fee".to_string(),
                        value: BigInt::from(30).to_signed_bytes_le(),
                        change: ChangeType::Creation.into(),
                    },
                ],
                change: i32::from(ChangeType::Creation),
                protocol_type: Option::from(ProtocolType {
                    name: "UniswapV2".to_string(),
                    financial_type: FinancialType::Swap.into(),
                    attribute_schema: vec![],
                    implementation_type: ImplementationType::Custom.into(),
                }),
            }],
            balance_changes: vec![],
        })
    }
}
