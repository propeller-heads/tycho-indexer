use std::{
    str::FromStr,
    sync::mpsc::{Receiver, Sender},
};

use ethers::types::{H160, U256};
use graph::{
    graph::{Path, ProtoGraph},
    tick::Tick,
};
use models::{ERC20Token, Opportunity};
use protocol::models::{Pair, PairProperties};

pub mod graph;
pub mod models;
pub mod optimize;
pub mod protocol;
mod u256_num;

fn backrun_solver(p: Path) -> Option<Opportunity> {
    Some(p.get_swaps(U256::one()).unwrap())
}

pub fn search_opportunities(tick_rx: Receiver<Tick>, opp_tx: Sender<Opportunity>) {
    let mut graph = ProtoGraph::new(4);
    let initialiased = false;
    let start_tokens: Vec<H160> = Vec::new();
    let mut updated_addresses: Vec<H160> = Vec::new();
    loop {
        let tick = tick_rx.recv().expect("Receive of tick failed!");
        if !initialiased {
            for (addr, state) in tick.states.into_iter() {
                let prop: PairProperties = PairProperties {
                    address: addr,
                    tokens: vec![ERC20Token::new("0x", 18, "USDC")],
                };
                let pair = Pair(prop, state);
                graph.insert_pair(pair);
            }
            for t in start_tokens.iter() {
                graph.build_paths(*t);
            }
        } else {
            for (addr, state) in tick.states.into_iter() {
                updated_addresses.push(addr);
                // TODO: update graph
            }
        }
        let new_opps = graph.search_opportunities(backrun_solver, Some(updated_addresses.clone()));
        for opp in new_opps.into_iter() {
            opp_tx.send(opp).expect("Sending opportunity failed!")
        }
    }
}
