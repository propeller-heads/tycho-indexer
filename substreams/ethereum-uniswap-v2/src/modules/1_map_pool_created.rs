use std::str::FromStr;

use ethabi::ethereum_types::Address;
use substreams::prelude::BigInt;
use substreams_ethereum::pb::eth::v2::{self as eth};

use substreams_helper::{event_handler::EventHandler, hex::Hexable};

use crate::{
    abi::factory::events::PairCreated,
    pb::tycho::evm::v1::{
        Attribute, Block, BlockEntityChanges, ChangeType, EntityChanges, FinancialType, ImplementationType, ProtocolComponent, ProtocolType, Transaction, TransactionEntityChanges
    },
};

#[substreams::handlers::map]
pub fn map_pools_created(
    params: String,
    block: eth::Block,
) -> Result<BlockEntityChanges, substreams::errors::Error> {
    let mut new_pools: Vec<TransactionEntityChanges> = vec![];

    let factory_address = params.as_str();

    get_pools(&block, &mut new_pools, factory_address);

    let tycho_block: Block = block.into();

    Ok(BlockEntityChanges { block: Some(tycho_block), changes: new_pools })
}

fn get_pools(
    block: &eth::Block,
    new_pools: &mut Vec<TransactionEntityChanges>,
    factory_address: &str,
) {
    // Extract new pools from PairCreated events
    let mut on_pair_created = |event: PairCreated, _tx: &eth::TransactionTrace, _log: &eth::Log| {
        let tycho_tx: Transaction = _tx.into();

        new_pools.push(TransactionEntityChanges {
            tx: Some(tycho_tx),
            entity_changes: vec![EntityChanges {
                component_id: event.pair.to_hex(),
                attributes: vec![
                    Attribute {
                        name: "reserve0".to_string(),
                        value: BigInt::from(0).to_signed_bytes_le(),
                        change: ChangeType::Creation.into(),
                    },
                    Attribute {
                        name: "reserve1".to_string(),
                        value: BigInt::from(0).to_signed_bytes_le(),
                        change: ChangeType::Creation.into(),
                    },
                ],
            }],
            component_changes: vec![ProtocolComponent {
                id: event.pair.to_hex(),
                tokens: vec![event.token0, event.token1],
                contracts: vec![],
                static_att: vec![
                    // Trading Fee is hardcoded to 0.3%, saved as int in bps (basis points)
                    Attribute {
                        name: "fee".to_string(),
                        value: BigInt::from(30).to_signed_bytes_le(),
                        change: ChangeType::Creation.into(),
                    },
                    Attribute {
                        name: "pool_address".to_string(),
                        value: event.pair,
                        change: ChangeType::Creation.into(),
                    },
                ],
                change: i32::from(ChangeType::Creation),
                protocol_type: Some(ProtocolType {
                    name: "uniswap_v2_pool".to_string(),
                    financial_type: FinancialType::Swap.into(),
                    attribute_schema: vec![],
                    implementation_type: ImplementationType::Custom.into(),
                }),
            }],
            balance_changes: vec![],
        })
    };

    let mut eh = EventHandler::new(block);

    eh.filter_by_address(vec![Address::from_str(factory_address).unwrap()]);

    eh.on::<PairCreated, _>(&mut on_pair_created);
    eh.handle_events();
}
