use std::str::FromStr;

use ethabi::ethereum_types::Address;
use substreams::prelude::BigInt;
use substreams_ethereum::pb::eth::v2::{self as eth};

use substreams_helper::{event_handler::EventHandler, hex::Hexable};

use crate::{
    abi::factory::events::PairCreated,
    pb::tycho::evm::v1::{
        Attribute, ChangeType, FinancialType, ImplementationType, ProtocolComponent, ProtocolType,
        SameTypeTransactionChanges, Transaction, TransactionEntityChanges,
    },
};

#[substreams::handlers::map]
pub fn map_pools_created(
    block: eth::Block,
) -> Result<SameTypeTransactionChanges, substreams::errors::Error> {
    let mut new_pools: Vec<TransactionEntityChanges> = vec![];

    get_pools(&block, &mut new_pools);
    Ok(SameTypeTransactionChanges { changes: new_pools })
}

fn get_pools(block: &eth::Block, new_pools: &mut Vec<TransactionEntityChanges>) {
    // Extract new pools from PairCreated events
    let mut on_pair_created = |event: PairCreated, _tx: &eth::TransactionTrace, _log: &eth::Log| {
        let tycho_tx: Transaction = _tx.into();

        new_pools.push(TransactionEntityChanges {
            tx: Option::from(tycho_tx),
            entity_changes: vec![],
            component_changes: vec![ProtocolComponent {
                id: event.pair.to_hex(),
                tokens: vec![event.token0, event.token1],
                contracts: vec![event.pair],
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
    };

    let mut eh = EventHandler::new(&block);

    // TODO: Parametrize Factory Address
    eh.filter_by_address(vec![
        Address::from_str("0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f").unwrap()
    ]);

    eh.on::<PairCreated, _>(&mut on_pair_created);
    eh.handle_events();
}
