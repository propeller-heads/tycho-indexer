use std::str::FromStr;

use ethabi::ethereum_types::Address;
use substreams_ethereum::pb::eth::v2::{self as eth};
use substreams_helper::event_handler::EventHandler;

use crate::{
    abi::Factory::events::PairCreated,
    common::{constants, helpers::TokenContract},
    pb::tycho::evm::uniswap::v2::{Pool, Pools},
};

#[substreams::handlers::map]
pub fn map_pool_created(block: eth::Block) -> Result<Pools, substreams::errors::Error> {
    let mut pools: Vec<Pool> = vec![];

    get_pools(&block, &mut pools);
    Ok(Pools { pools })
}

fn get_pools(block: &eth::Block, pools: &mut Vec<Pool>) {
    let mut on_pair_created = |event: PairCreated, _tx: &eth::TransactionTrace, _log: &eth::Log| {
        let pool = TokenContract::new(Address::from_slice(event.pair.as_slice())).as_struct();
        let token0 = TokenContract::new(Address::from_slice(event.token0.as_slice())).as_struct();
        let token1 = TokenContract::new(Address::from_slice(event.token1.as_slice())).as_struct();

        pools.push(Pool {
            name: format! {"{}/{}", token0.symbol, token1.symbol},
            symbol: String::new(),
            address: pool.address.clone(),
            input_tokens: Some(Erc20Tokens { items: vec![token0, token1] }),
            output_token: Some(pool),
            created_timestamp: block.timestamp_seconds() as i64,
            created_block_number: block.number as i64,
        })
    };

    let mut eh = EventHandler::new(&block);
    eh.filter_by_address(vec![Address::from_str(constants::UNISWAP_V2_FACTORY).unwrap()]);

    eh.on::<PairCreated, _>(&mut on_pair_created);
    eh.handle_events();
}
