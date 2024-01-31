use std::str::FromStr;

use ethabi::ethereum_types::Address;
use substreams_ethereum::pb::eth::v2::{self as eth};

use substreams_helper::{event_handler::EventHandler, hex::Hexable};

use crate::{
    abi::factory::events::PoolCreated,
    pb::tycho::evm::v1::{
        Attribute, ChangeType, FinancialType, ImplementationType, ProtocolComponent, ProtocolType,
        SameTypeTransactionChanges, Transaction, TransactionEntityChanges,
    },
};

// TODO: Parametrize Factory Address
const UNISWAP_V3_FACTORY_ADDRESS: &str = "0x1F98431c8aD98523631AE4a59f267346ea31F984";

#[substreams::handlers::map]
pub fn map_pools_created(
    block: eth::Block,
) -> Result<SameTypeTransactionChanges, substreams::errors::Error> {
    let mut new_pools: Vec<TransactionEntityChanges> = vec![];

    get_new_pools(&block, &mut new_pools);
    Ok(SameTypeTransactionChanges { changes: new_pools })
}

fn get_new_pools(block: &eth::Block, new_pools: &mut Vec<TransactionEntityChanges>) {
    // Extract new pools from PoolCreated events
    let mut on_pair_created = |event: PoolCreated, _tx: &eth::TransactionTrace, _log: &eth::Log| {
        let tycho_tx: Transaction = _tx.into();

        new_pools.push(TransactionEntityChanges {
            tx: Option::from(tycho_tx),
            entity_changes: vec![],
            component_changes: vec![ProtocolComponent {
                id: event.pool.to_hex(),
                tokens: vec![event.token0, event.token1],
                contracts: vec![event.pool],
                static_att: vec![
                    Attribute {
                        name: "fee".to_string(),
                        value: event.fee.to_signed_bytes_le(),
                        change: ChangeType::Creation.into(),
                    },
                    Attribute {
                        name: "tick_spacing".to_string(),
                        value: event.tick_spacing.to_signed_bytes_le(),
                        change: ChangeType::Creation.into(),
                    },
                ],
                change: i32::from(ChangeType::Creation),
                protocol_type: Option::from(ProtocolType {
                    name: "UniswapV3".to_string(),
                    financial_type: FinancialType::Swap.into(),
                    attribute_schema: vec![],
                    implementation_type: ImplementationType::Custom.into(),
                }),
            }],
            balance_changes: vec![],
        })
    };

    let mut eh = EventHandler::new(block);

    eh.filter_by_address(vec![Address::from_str(UNISWAP_V3_FACTORY_ADDRESS).unwrap()]);

    eh.on::<PoolCreated, _>(&mut on_pair_created);
    eh.handle_events();
}
