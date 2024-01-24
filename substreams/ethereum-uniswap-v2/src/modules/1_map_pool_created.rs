use std::str::FromStr;

use ethabi::ethereum_types::Address;
use substreams_ethereum::pb::eth::v2::{self as eth};
use substreams_helper::event_handler::EventHandler;

use crate::{
    abi::factory::events::PairCreated,
    pb::tycho::evm::uniswap::v2::{Pool, Pools},
};

#[substreams::handlers::map]
pub fn map_pool_created(block: eth::Block) -> Result<Pools, substreams::errors::Error> {
    let mut pools: Vec<Pool> = vec![];

    get_pools(&block, &mut pools);
    Ok(Pools { pools })
}

fn get_pools(block: &eth::Block, pools: &mut Vec<Pool>) {
    // Extract new pools from PairCreated events
    let mut on_pair_created = |event: PairCreated, _tx: &eth::TransactionTrace, _log: &eth::Log| {
        pools.push(Pool {
            address: Vec::from(event.pair.as_slice()),
            token0: Vec::from(event.token0.as_slice()),
            token1: Vec::from(event.token1.as_slice()),
            created_timestamp: block.timestamp_seconds() as i64,
            created_block_number: block.number as i64,
            created_tx_hash: block.hash.clone(),
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
