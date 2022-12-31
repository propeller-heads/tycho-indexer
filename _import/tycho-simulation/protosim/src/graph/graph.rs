use ethers::types::{H160, U256};
use itertools::Itertools;
use petgraph::{
    algo::all_simple_paths,
    prelude::UnGraph,
    stable_graph::{EdgeIndex, NodeIndex},
    visit::EdgeRef,
};
use std::collections::HashMap;

use crate::{
    models::{ERC20Token, Opportunity, Swap},
    protocol::{
        errors::TradeSimulationError,
        models::{GetAmountOutResult, Pair},
        state::ProtocolSim,
    },
};

use super::edge_paths::all_edge_paths;

struct TokenEntry(NodeIndex, ERC20Token);

struct Path<'a> {
    pairs: &'a [&'a Pair],
    tokens: &'a [&'a ERC20Token],
}

impl Path<'_> {
    fn price(&self) -> f64 {
        let mut p = 1.0;
        for i in 0..self.pairs.len() {
            let st = self.tokens[i];
            let et = self.tokens[i + 1];
            let Pair(_, state) = self.pairs[i];
            p = p * state.spot_price(st, et);
        }
        return p;
    }

    fn get_amount_out(&self, amount_in: U256) -> Result<GetAmountOutResult, TradeSimulationError> {
        let mut res = GetAmountOutResult::new(amount_in, U256::zero());
        for i in 0..self.pairs.len() {
            let st = self.tokens[i];
            let et = self.tokens[i + 1];
            let Pair(_, state) = self.pairs[i];
            res.aggregate(&state.get_amount_out(res.amount, st, et)?);
        }
        Ok(res)
    }

    fn get_swaps(&self, amount_in: U256) -> Result<Opportunity, TradeSimulationError> {
        // if we could replace this one with ArrayVec we could shrink this to a single method.
        let mut swaps = Vec::<_>::new();
        let mut res = GetAmountOutResult::new(U256::zero(), U256::zero());
        let mut current_amount = amount_in;
        for i in 0..self.pairs.len() {
            let st = self.tokens[i];
            let et = self.tokens[i + 1];
            let Pair(properties, state) = self.pairs[i];
            res.aggregate(&state.get_amount_out(current_amount, st, et)?);
            swaps.push(Swap::new(
                st.address,
                current_amount,
                et.address,
                res.amount,
                properties.address,
            ));
            current_amount = res.amount;
        }
        Ok(Opportunity::new(swaps, res.gas))
    }
}

pub struct ProtoGraph {
    n_hops: usize,
    tokens: HashMap<H160, TokenEntry>,
    states: HashMap<H160, Pair>,
    graph: UnGraph<H160, H160>,
    paths: Vec<Vec<EdgeIndex>>,
}

impl ProtoGraph {
    pub fn new(n_hops: usize) -> Self {
        ProtoGraph {
            n_hops: n_hops,
            tokens: HashMap::new(),
            states: HashMap::new(),
            graph: UnGraph::new_undirected(),
            paths: Vec::new(),
        }
    }
    pub fn insert_pair(&mut self, Pair(properties, state): Pair) -> Option<Pair> {
        // add missing tokens to graph
        for token in properties.tokens.iter() {
            if !self.tokens.contains_key(&token.address) {
                let node_idx = self.graph.add_node(token.address);
                self.tokens
                    .insert(token.address, TokenEntry(node_idx, token.clone()));
            }
        }

        // add edges
        for tpair in properties.tokens.iter().combinations(2) {
            let &TokenEntry(t0, _) = self.tokens.get(&tpair[0].address).expect("token missing");
            let &TokenEntry(t1, _) = self.tokens.get(&tpair[1].address).expect("token missing");

            self.graph.add_edge(t0, t1, properties.address);
        }

        // record pair
        self.states
            .insert(properties.address, Pair(properties, state))
    }

    pub fn build_paths(&mut self, start_token: H160) {
        let TokenEntry(node_idx, _) = self.tokens[&start_token];
        let edge_paths =
            all_edge_paths::<Vec<_>, _>(&self.graph, node_idx, node_idx, 1, Some(self.n_hops + 1));
        for path in edge_paths {
            // Only insert normalised path if we don't already have it present.
            if let Err(pos) = self.paths.binary_search(&path) {
                self.paths.insert(pos, path)
            };
        }
        self.paths.shrink_to_fit();
    }


    pub fn iter_paths(){
        
    }

    pub fn search_opportunities(&self) -> Vec<Opportunity> {
        let mut pairs = Vec::with_capacity(self.n_hops);
        let mut tokens = Vec::with_capacity(self.n_hops + 1);
        // allocates only if there is an opportunity
        let mut opportunities = Vec::new();
        for path in self.paths.iter() {
            pairs.clear();
            tokens.clear();
            let mut first = true;
            for edge_idx in path.iter() {
                let state_addr = self.graph.edge_weight(*edge_idx).unwrap();
                let state = self.states.get(state_addr).unwrap();
                let (s_idx, e_idx) = self.graph.edge_endpoints(*edge_idx).unwrap();
                let TokenEntry(_, end) = &self.tokens[self.graph.node_weight(e_idx).unwrap()];
                if first {
                    let TokenEntry(_, start) = &self.tokens[self.graph.node_weight(s_idx).unwrap()];
                    tokens.push(start);
                }
                pairs.push(state);
                tokens.push(end);
                first = false;
            }
            let p = Path {
                pairs: &pairs,
                tokens: &tokens,
            };
            let price = p.price();
            if price > 1.0 {
                let amount_in = optimize_path(&p);
                if amount_in > U256::zero() {
                    opportunities.push(p.get_swaps(amount_in).unwrap());
                }
            }
        }
        return opportunities;
    }
}

fn optimize_path(p: &Path) -> U256 {
    let res = p.get_amount_out(U256::from(10_000_000)).unwrap();
    return U256::from(1_000_000)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rstest::rstest;
    use crate::protocol::models::PairProperties;
    use crate::protocol::uniswap_v2::state::UniswapV2State;

    use super::*;

    use super::ProtoGraph;

    #[test]
    fn test_insert_pair() {
        let mut g = ProtoGraph::new(4);
        let pair = make_pair(
            "0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8",
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 ",
            2000,
            2000,
        );

        let res = g.insert_pair(pair);

        assert!(res.is_none());
        assert_eq!(g.tokens.len(), 2);
        assert_eq!(g.states.len(), 1);
        assert_eq!(g.graph.edge_count(), 1);
        assert_eq!(g.graph.node_count(), 2);
    }

    fn make_pair(pair: &str, t0: &str, t1: &str, r0: u64, r1: u64) -> Pair {
        let t0 = ERC20Token::new(t0, 3, "T0");
        let t1 = ERC20Token::new(t1, 3, "T1");
        let props = PairProperties {
            address: H160::from_str(pair).unwrap(),
            tokens: vec![t0, t1],
        };
        let state = UniswapV2State::new(U256::from(r0), U256::from(r1)).into();
        Pair(props, state)
    }

    #[rstest]
    #[case::simple_triangle(
        &[
            (
                "0x0000000000000000000000000000000000000001", 
                "0x0000000000000000000000000000000000000001",
                "0x0000000000000000000000000000000000000002"
            ), 
            (
                "0x0000000000000000000000000000000000000002",
                "0x0000000000000000000000000000000000000003",
                "0x0000000000000000000000000000000000000002",
            ),
            (
                "0x0000000000000000000000000000000000000003",
                "0x0000000000000000000000000000000000000001",
                "0x0000000000000000000000000000000000000003 ",
            )
        ], 
    vec![
        vec![
            "0x0000000000000000000000000000000000000001", 
            "0x0000000000000000000000000000000000000002", 
            "0x0000000000000000000000000000000000000003"
        ],
        vec![
            "0x0000000000000000000000000000000000000003", 
            "0x0000000000000000000000000000000000000002", 
            "0x0000000000000000000000000000000000000001"
        ]
    ])]
    #[case::double_pool(
        &[
            (
                "0x0000000000000000000000000000000000000001", 
                "0x0000000000000000000000000000000000000001",
                "0x0000000000000000000000000000000000000002"
            ), 
            (
                "0x0000000000000000000000000000000000000002",
                "0x0000000000000000000000000000000000000001",
                "0x0000000000000000000000000000000000000002"
            ),
        ],
        vec![
            vec![
                "0x0000000000000000000000000000000000000001", 
                "0x0000000000000000000000000000000000000002"
            ],
            vec![
                "0x0000000000000000000000000000000000000002",    
                "0x0000000000000000000000000000000000000001", 
            ]
        ]
    )]
    #[case::diamond_doubled_edges(
        &[
            (
                "0x0000000000000000000000000000000000000001", 
                "0x0000000000000000000000000000000000000001",
                "0x0000000000000000000000000000000000000002"
            ), 
            (
                "0x0000000000000000000000000000000000000002",
                "0x0000000000000000000000000000000000000002",
                "0x0000000000000000000000000000000000000003"
            ),
            (
                "0x0000000000000000000000000000000000000003",
                "0x0000000000000000000000000000000000000003",
                "0x0000000000000000000000000000000000000004"
            ),
            (
                "0x0000000000000000000000000000000000000004",
                "0x0000000000000000000000000000000000000001",
                "0x0000000000000000000000000000000000000004",
            ),
            (
                "0x0000000000000000000000000000000000000005",
                "0x0000000000000000000000000000000000000002",
                "0x0000000000000000000000000000000000000003",
            ),
            (
                "0x0000000000000000000000000000000000000006",
                "0x0000000000000000000000000000000000000003",
                "0x0000000000000000000000000000000000000004",
            ),
        ],
        vec![
            vec![
                "0x0000000000000000000000000000000000000001", 
                "0x0000000000000000000000000000000000000002",
                "0x0000000000000000000000000000000000000003",
                "0x0000000000000000000000000000000000000004",
            ],
            vec![
                "0x0000000000000000000000000000000000000001", 
                "0x0000000000000000000000000000000000000002",
                "0x0000000000000000000000000000000000000006",
                "0x0000000000000000000000000000000000000004",
            ],
            vec![
                "0x0000000000000000000000000000000000000001", 
                "0x0000000000000000000000000000000000000005",
                "0x0000000000000000000000000000000000000003",
                "0x0000000000000000000000000000000000000004",
            ],
            vec![
                "0x0000000000000000000000000000000000000001", 
                "0x0000000000000000000000000000000000000005",
                "0x0000000000000000000000000000000000000006",
                "0x0000000000000000000000000000000000000004",
            ],
            // reverse versions
            vec![
                "0x0000000000000000000000000000000000000004",
                "0x0000000000000000000000000000000000000003",
                "0x0000000000000000000000000000000000000002",
                "0x0000000000000000000000000000000000000001", 
            ],
            vec![
                "0x0000000000000000000000000000000000000004",
                "0x0000000000000000000000000000000000000003",
                "0x0000000000000000000000000000000000000005",
                "0x0000000000000000000000000000000000000001", 
            ],
            vec![
                "0x0000000000000000000000000000000000000004",
                "0x0000000000000000000000000000000000000006",
                "0x0000000000000000000000000000000000000002",
                "0x0000000000000000000000000000000000000001", 
            ],
            
            vec![
                "0x0000000000000000000000000000000000000004",
                "0x0000000000000000000000000000000000000006",
                "0x0000000000000000000000000000000000000005",
                "0x0000000000000000000000000000000000000001",                 
            ],
        ]
    )]
    fn test_build_paths(#[case] pairs: &[(&str, &str, &str)], #[case] exp: Vec<Vec<&str>>) {
        let mut g = ProtoGraph::new(4);
        let exp: Vec<_> = exp.iter().map(|v| v.iter().map(|s| H160::from_str(s).unwrap()).collect::<Vec<_>>()).collect();
        for p in pairs {
            g.insert_pair(make_pair(
                p.0,
                p.1,
                p.2,
                2000,
                2000,
            ));
        }

        g.build_paths(H160::from_str("0x0000000000000000000000000000000000000001").unwrap());

        let mut paths = Vec::with_capacity(g.paths.len());
        for p in g.paths {
            let addr_path: Vec<_> = p.iter().map(|x| *g.graph.edge_weight(*x).unwrap()).collect();
            paths.push(addr_path);
        }
        assert_eq!(paths, exp);
    }

    #[rstest]
    fn test_simulate_path() {
        let mut g = ProtoGraph::new(4);
        g.insert_pair(make_pair(
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
            20_000_000,
            20_000_000,
        ));
        g.insert_pair(make_pair(
            "0x0000000000000000000000000000000000000002",
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
            20_000_000,
            10_000_000,
        ));
        g.build_paths(H160::from_str("0x0000000000000000000000000000000000000001").unwrap());
        let opps = g.search_opportunities();

        assert!(opps.len() > 0);
    }
}
