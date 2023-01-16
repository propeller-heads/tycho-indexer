use ethers::types::{H160, U256};
use itertools::Itertools;
use petgraph::{
    prelude::UnGraph,
    stable_graph::{EdgeIndex, NodeIndex},

};
use std::collections::HashMap;

use crate::{
    models::{ERC20Token, Opportunity, Swap},
    protocol::{
        errors::TradeSimulationError,
        models::{GetAmountOutResult, Pair},
        state::{ProtocolSim, ProtocolState},
    },
};

use super::edge_paths::all_edge_paths;

struct TokenEntry(NodeIndex, ERC20Token);

pub struct Path<'a> {
    pairs: &'a [&'a Pair],
    tokens: &'a [&'a ERC20Token],
}

impl <'a>Path<'a> {

    fn new(tokens: &'a Vec<&ERC20Token>, pairs: &'a Vec<&Pair>) -> Path<'a> {
        Path {
            pairs: &pairs,
            tokens: &tokens,
        }
    }

    pub fn price(&self) -> f64 {
        let mut p = 1.0;
        for i in 0..self.pairs.len() {
            let st = self.tokens[i];
            let et = self.tokens[i + 1];
            let Pair(_, state) = self.pairs[i];
            p = p * state.spot_price(st, et);
        }
        return p;
    }

    pub fn get_amount_out(&self, amount_in: U256) -> Result<GetAmountOutResult, TradeSimulationError> {
        let mut res = GetAmountOutResult::new(amount_in, U256::zero());
        for i in 0..self.pairs.len() {
            let st = self.tokens[i];
            let et = self.tokens[i + 1];
            let Pair(_, state) = self.pairs[i];
            res.aggregate(&state.get_amount_out(res.amount, st, et)?);
        }
        Ok(res)
    }

    pub fn get_swaps(&self, amount_in: U256) -> Result<Opportunity, TradeSimulationError> {
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


struct KeySubsetIterator<'a>{
    keys: Vec<H160>,
    data: &'a HashMap<H160, Vec<usize>>,
    key_idx: usize,
    vec_idx: usize,
}

impl <'a>KeySubsetIterator<'a>{
    fn new(keys: Option<Vec<H160>>, data: &'a HashMap<H160, Vec<usize>>) -> Self {
        if let Some(subset) = keys {
            KeySubsetIterator{
                keys: subset,
                data: data,
                key_idx: 0,
                vec_idx: 0,
            }
        } else {
            let subset = data.keys().map(|x| *x).collect::<Vec<_>>();
            KeySubsetIterator{
                keys: subset,
                data: data,
                key_idx: 0,
                vec_idx: 0,
            }
        }
        
    }
}

impl Iterator for KeySubsetIterator<'_>{
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        while self.key_idx < self.keys.len() {
            let addr = self.keys[self.key_idx];
            match self.data.get(&addr) {
                Some(path_indices) => {
                    if self.vec_idx + 1 >= path_indices.len() {
                        // we are at the last entry for this vec
                        self.vec_idx = 0;
                        self.key_idx += 1; 
                    } else {
                        self.vec_idx += 1;
                    }
                    return Some(*path_indices.get(self.vec_idx).expect("KeySubsetIterator: data was empty!"));
                },
                None => {
                    self.key_idx += 1;
                    continue;
                },
            };
        }
        None
    }
}


#[derive(PartialEq, PartialOrd, Eq, Ord, Debug)]
struct PathEntry{
    start: NodeIndex, 
    edges: Vec<EdgeIndex>,
}

impl PathEntry {
    fn new(start: NodeIndex, edges: Vec<EdgeIndex>) -> Self{
        PathEntry{
            start, edges
        }
    }
}

pub struct ProtoGraph {
    n_hops: usize,
    tokens: HashMap<H160, TokenEntry>,
    states: HashMap<H160, Pair>,
    graph: UnGraph<H160, H160>,
    paths: Vec<PathEntry>,
    path_memberships: HashMap<H160, Vec<usize>>,
}

impl ProtoGraph {
    pub fn new(n_hops: usize) -> Self {
        ProtoGraph {
            n_hops: n_hops,
            tokens: HashMap::new(),
            states: HashMap::new(),
            graph: UnGraph::new_undirected(),
            paths: Vec::new(),
            path_memberships: HashMap::new(),
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

    pub fn update_state(&mut self, address: &H160, state: ProtocolState) -> Option<()> {
        if let Some(pair) = self.states.get_mut(address) {
            pair.1 = state;
            return Some(());
        }
        None
    }

    pub fn build_paths(&mut self, start_token: H160) {
        let TokenEntry(node_idx, _) = self.tokens[&start_token];
        let edge_paths =
            all_edge_paths::<Vec<_>, _>(&self.graph, node_idx, node_idx, 1, Some(self.n_hops));
        println!("Exploring paths");
        for path in edge_paths {
            // insert path only if it does not yet exist
            let entry = PathEntry::new(node_idx, path);
            if let Err(pos) = self.paths.binary_search(&entry) {
                self.paths.insert(pos, entry);
            };
        }
        println!("Building membership cache");
        for pos in 0..self.paths.len() {
            // build membership cache
            for edge_idx in self.paths[pos].edges.iter() {
                let addr = *self.graph.edge_weight(*edge_idx).unwrap();
                if let Some(path_indices) = self.path_memberships.get_mut(&addr) {
                    path_indices.push(pos);
                } else {
                    self.path_memberships.insert(addr, vec![pos]);
                }
            }
        }
        self.paths.shrink_to_fit();
    }

    pub fn search_opportunities<F:Fn(Path) -> Option<Opportunity>>(&self, search: F, involved_addresses: Option<Vec<H160>>) -> Vec<Opportunity> {
        // PERF: .unique() allocates a hash map in the background, also pairs and token vectors allocate.
        // This is suboptimal for performance, I decided to leave this here though as it will simplify parallelisation.
        // To optimize this, each worker needs a preallocated collections that are cleared on each invocation.
        let mut pairs = Vec::with_capacity(self.n_hops);
        let mut tokens = Vec::with_capacity(self.n_hops + 1);
        // allocates only if there is an opportunity
        let mut opportunities = Vec::new();
        // KeySubsetIterator will return a list of path ids we make sure the path ids are unique and yield the
        // corresponding PathEntry object. This way we get all paths that contain any of the changed addresses.
        // In case we didn't see some address on any path (KeyError on path_memberhips) it is simply skipped.
        let path_iter = KeySubsetIterator::new(involved_addresses, &self.path_memberships).unique().map(|idx| &self.paths[idx]);
        let mut n_paths_evaluated: u64 = 0;
        for path in path_iter {
            pairs.clear();
            tokens.clear();
            let mut prev_node_idx = path.start;
            let TokenEntry(_, start) = &self.tokens[self.graph.node_weight(path.start).unwrap()];
            tokens.push(start);
            for edge_idx in path.edges.iter() {
                let state_addr = self.graph.edge_weight(*edge_idx).unwrap();
                let state = self.states.get(state_addr).unwrap();
                let (s_idx, e_idx) = self.graph.edge_endpoints(*edge_idx).unwrap();
                // we need to correctly infer the edge direction here
                let next_token = if prev_node_idx == s_idx {
                    prev_node_idx = e_idx;
                    &self.tokens[self.graph.node_weight(e_idx).unwrap()].1
                } else if prev_node_idx == e_idx {
                    prev_node_idx = s_idx;
                    &self.tokens[self.graph.node_weight(s_idx).unwrap()].1
                } else {
                    panic!("Paths node indices did not connect!")
                };
                pairs.push(state);
                tokens.push(next_token);
            }
            let p = Path::new(&tokens, &pairs);
            n_paths_evaluated += 1;
            if let Some(opp) = search(p) {
                opportunities.push(opp);
            }
        }
        println!("Searched {} paths", n_paths_evaluated);
        return opportunities;
    }

    pub fn info(&self){
        println!("ProtoGraph(n_hops={}) Stats:", self.n_hops);
        println!("States: {}", self.states.len());
        println!("Nodes: {}", self.tokens.len());
        println!("Paths: {}", self.paths.len());
        println!("Membership Cache: {}", self.path_memberships.len());
    }
}



#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ethers::types::{I256, Sign};
    use rstest::rstest;
    use crate::optimize::gss::gss;
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

    #[test]
    fn test_update_state() {
        let mut g = ProtoGraph::new(4);
        let pair = make_pair(
            "0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8",
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            2000,
            2000,
        );
        let address = pair.0.address;
        let Pair(_, state) = make_pair(
            "0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8",
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            1000,
            2000,
        );
        g.insert_pair(pair);

        g.update_state(&address, state.clone());
        let Pair(_, updated) = &g.states[&address];

        assert_eq!(updated.clone(), state);
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
            let addr_path: Vec<_> = p.edges.iter().map(|x| *g.graph.edge_weight(*x).unwrap()).collect();
            paths.push(addr_path);
        }
        assert_eq!(paths, exp);
    }

    fn atomic_arb_finder(p: Path) -> Option<Opportunity> {
        let price = p.price();
        if price > 1.0 {
            let amount_in = optimize_path(&p);
            if amount_in > U256::zero() {
                let opp = p.get_swaps(amount_in).unwrap();
                let last = &opp.actions()[opp.actions().len() - 1];
                if last.amount_out() > amount_in {
                    return Some(opp);
                }
                return None;
            }
        }
        None
    }

    fn optimize_path(p: &Path) -> U256 {
        let sim_arb = |amount_in:I256| {
            let amount_in_unsigned = if amount_in > I256::zero() { amount_in.into_raw()} else {U256::zero()};

            let amount_out_unsigned;
            match p.get_amount_out(amount_in_unsigned) {
                Ok(res) => {
                    amount_out_unsigned = res.amount;
                }
                Err(tse) => {
                    if let Some(res) = tse.partial_result {
                        amount_out_unsigned = res.amount;
                    } else {
                        amount_out_unsigned = U256::zero();
                    }
                } 
            }
            let amount_out = I256::checked_from_sign_and_abs(Sign::Positive, amount_out_unsigned).unwrap();
            let profit = amount_out - amount_in;
            return profit;
        };
        let res = gss(sim_arb, U256::one(), U256::from(100_000), I256::one(), 100, false);
        return res.0;
    }

    #[rstest]
    #[case(Some(vec![H160::from_str("0x0000000000000000000000000000000000000001").unwrap()]))]
    #[case(None)]
    fn test_simulate_path(#[case] addresses: Option<Vec<H160>>) {
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
        let opps = g.search_opportunities(atomic_arb_finder, addresses);

        assert_eq!(opps.len(), 1);
    }

    #[rstest]
    #[case::empty(HashMap::new(), None, vec![])]
    #[case::empty_keys(HashMap::from([(H160::from_low_u64_be(1), vec![1,2]), (H160::from_low_u64_be(2), vec![3,4]),]), Some(vec![]), vec![])]
    #[case::one_key(HashMap::from([(H160::from_low_u64_be(1), vec![1,2]), (H160::from_low_u64_be(2), vec![3,4]),]), Some(vec![H160::from_low_u64_be(2)]), vec![3,4])]
    #[case::one_key(HashMap::from([(H160::from_low_u64_be(1), vec![1,2]), (H160::from_low_u64_be(2), vec![3,4]),]), Some(vec![H160::from_low_u64_be(1)]), vec![1,2])]
    #[case::two_keys(HashMap::from([(H160::from_low_u64_be(1), vec![1]), (H160::from_low_u64_be(2), vec![3,4]),]), Some(vec![H160::from_low_u64_be(1), H160::from_low_u64_be(2)]), vec![1,3,4])]
    fn test_key_subset_iterator(#[case] data: HashMap<H160, Vec<usize>>, #[case] keys: Option<Vec<H160>>, #[case] exp: Vec<usize> ){
        let it = KeySubsetIterator::new(keys, &data);

        let mut res: Vec<_> = it.collect();
        res.sort();

        assert_eq!(res, exp);
    }

    #[test]
    fn test_path_price(){
        let pair_0 = make_pair(
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
            20_000_000,
            10_000_000,
        );
        let pair_1 = make_pair(
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
            20_000_000,
            25_000_000,
        );
        let Pair(props, _ ) = &pair_0;
        let tokens = vec![&props.tokens[0], &props.tokens[1], &props.tokens[0]];
        let pairs = vec![&pair_0, &pair_1];
        let path = Path::new(&tokens, &pairs);

        let res = path.price();

        assert_eq!(res, 0.4);
    }

    #[test]
    fn test_get_amount_out(){
        let pair_0 = make_pair(
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
            20_000_000,
            10_000_000,
        );
        let pair_1 = make_pair(
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
            20_000_000,
            25_000_000,
        );
        let Pair(props, _ ) = &pair_0;
        let tokens = vec![&props.tokens[0], &props.tokens[1], &props.tokens[0]];
        let pairs = vec![&pair_0, &pair_1];
        let path = Path::new(&tokens, &pairs);

        let res = path.get_amount_out(U256::from(100_000)).unwrap();

        assert_eq!(res.gas, U256::from(240_000));
        assert_eq!(res.amount, U256::from(39_484));
    }

    #[test]
    fn test_get_swaps(){
        let pair_0 = make_pair(
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
            20_000_000,
            10_000_000,
        );
        let pair_1 = make_pair(
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
            20_000_000,
            25_000_000,
        );
        let Pair(props, _ ) = &pair_0;
        let tokens = vec![&props.tokens[0], &props.tokens[1], &props.tokens[0]];
        let pairs = vec![&pair_0, &pair_1];
        let path = Path::new(&tokens, &pairs);
        let amount_in = U256::from(100_000);

        let res = path.get_swaps(amount_in).unwrap();
        let actions = res.actions();

        assert_eq!(actions[0].amount_in(), amount_in);
        assert_eq!(actions[0].amount_out(), actions[1].amount_in());
        assert_eq!(actions[1].amount_out(), U256::from(39_484))

    }
}
