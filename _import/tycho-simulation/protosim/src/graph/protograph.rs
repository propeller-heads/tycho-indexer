//! Protocol Graph
//!
//! This module contains the `ProtoGraph` struct, it represents a graph
//! of token exchange protocols (pools). The graph contains information
//! about the tokens on the nodes and protocol states on the edges.
//!
//! The graph helps to solve optimization problems that involve exchanging one token
//! for another.
//!
//! The graphs main methods are:
//!  - `new`: creates a new ProtoGraph struct with the given maximum number of hops.
//!  - `insert_pair`: Given a `Pair` struct, it adds missing tokens to the graph
//!         and creates edges between the tokens. It also records the pair in the states.
//!  - `build_routes`: this function should be called whenever the graphs topology
//!         changes such that the `search_opportunities` method can correctly take
//!         into account newly added edges.
//! - `transition_states`: This method can be called to transition states based on
//!         protocol events.
//! - `with_states_transitioned`: This method should be called to apply a change,
//!         query the graph and then immediately revert the changes again.
//!
//! # Examples
//! ```
//! use std::str::FromStr;
//!
//! use ethers::types::{H160, U256};
//! use protosim::graph::protograph::{ProtoGraph, Route};
//! use protosim::models::ERC20Token;
//! use protosim::protocol::models::{PairProperties, Pair};
//! use protosim::protocol::uniswap_v2::state::{UniswapV2State};
//!
//! let mut g = ProtoGraph::new(4);
//! let pair = {
//!     let t0 = ERC20Token::new("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 3, "T0");
//!     let t1 = ERC20Token::new("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 ", 3, "T1");
//!     let props = PairProperties {
//!         address: H160::from_str("0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8").unwrap(),
//!         tokens: vec![t0, t1],
//!     };
//!     let state = UniswapV2State::new(U256::from(2000), U256::from(2000)).into();
//!     Pair(props, state)
//! };
//!
//! let res = g.insert_pair(pair);
//!
//! g.info()
//! ```
use ethers::types::{H160, U256};
use itertools::Itertools;
use log::{debug, info, trace, warn};
use petgraph::{
    prelude::UnGraph,
    stable_graph::{EdgeIndex, NodeIndex},
};
use std::{collections::HashMap, error::Error};

use crate::{
    models::{ERC20Token, Swap, SwapSequence},
    protocol::{
        errors::{TradeSimulationError, TransitionError},
        events::{EVMLogMeta, LogIndex},
        models::{GetAmountOutResult, Pair},
        state::{ProtocolEvent, ProtocolSim, ProtocolState},
    },
};

use super::edge_routes::all_edge_routes;

struct TokenEntry(NodeIndex, ERC20Token);

#[derive(Debug)]
pub struct Route<'a> {
    pairs: &'a [&'a Pair],
    tokens: &'a [&'a ERC20Token],
}

impl<'a> Route<'a> {
    /// Represents a route of token trades through a series of pairs.
    ///
    /// Creates a new instance of the Route struct.
    /// - `tokens`: A reference to a vector of references to ERC20Token structs.
    /// - `pairs`: A reference to a vector of references to Pair structs.
    /// Returns a new instance of the Route struct.
    fn new(tokens: &'a Vec<&ERC20Token>, pairs: &'a Vec<&Pair>) -> Route<'a> {
        Route { pairs, tokens }
    }
    /// Calculates the price of the route.
    ///
    /// Returns the price of the route as a floating point number.
    pub fn price(&self) -> f64 {
        let mut p = 1.0;
        for i in 0..self.pairs.len() {
            let st = self.tokens[i];
            let et = self.tokens[i + 1];
            let Pair(_, state) = self.pairs[i];
            p *= state.spot_price(st, et);
        }
        p
    }
    /// Get the amount of output for a given input.
    ///
    /// ## Arguments
    /// - `amount_in`: A U256 representing the input amount.
    ///
    /// ## Returns
    /// A `Result` containing a `GetAmountOutResult` on success and a `TradeSimulationError` on failure.
    pub fn get_amount_out(
        &self,
        amount_in: U256,
    ) -> Result<GetAmountOutResult, TradeSimulationError> {
        let mut res = GetAmountOutResult::new(amount_in, U256::zero());
        for i in 0..self.pairs.len() {
            let st = self.tokens[i];
            let et = self.tokens[i + 1];
            let Pair(_, state) = self.pairs[i];
            res.aggregate(&state.get_amount_out(res.amount, st, et)?);
        }
        Ok(res)
    }

    /// Get the swaps for a given input.
    ///
    /// ## Arguments
    /// - `amount_in`: A U256 representing the input amount.
    ///
    /// ## Returns
    /// A `Result` containing a tuple of `(Vec<Swap>, U256)` on success and a `TradeSimulationError` on failure.
    pub fn get_swaps(&self, amount_in: U256) -> Result<(Vec<Swap>, U256), TradeSimulationError> {
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
        Ok((swaps, res.gas))
    }
}

struct RouteIdSubsetsByMembership<'a> {
    keys: Vec<H160>,
    data: &'a HashMap<H160, Vec<usize>>,
    key_idx: usize,
    vec_idx: usize,
}

impl<'a> RouteIdSubsetsByMembership<'a> {
    /// Create a new RouteIdSubsetsByMembership
    ///
    /// Basically this struct will iterate over the values of a subset of keys in a HashMap.
    /// If a subset is not provided, it will iterate over all keys in the HashMap.
    /// In this specific case, keys are addresses and each value is a collection of
    /// route ids which contain the corresponding pool. The iterator yields the individual
    /// route ids present in the corresponding values.
    ///
    /// # Arguments
    ///
    /// `addresses` - An optional subset of addresses to iterate over.
    /// `memberships` - The route memberships to iterate over.
    ///
    /// # Note
    /// This iterator can procude duplicated route ids. Especially if a route contains
    /// multiple pools. In most cases the user has to take care of deduplicating any
    /// repeated route ids if this is relevant for the corresponding use case.
    fn new(addresses: Option<Vec<H160>>, memberships: &'a HashMap<H160, Vec<usize>>) -> Self {
        if let Some(subset) = addresses {
            RouteIdSubsetsByMembership {
                keys: subset,
                data: memberships,
                key_idx: 0,
                vec_idx: 0,
            }
        } else {
            let subset = memberships.keys().copied().collect::<Vec<_>>();
            RouteIdSubsetsByMembership {
                keys: subset,
                data: memberships,
                key_idx: 0,
                vec_idx: 0,
            }
        }
    }
}

impl Iterator for RouteIdSubsetsByMembership<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        while self.key_idx < self.keys.len() {
            let addr = self.keys[self.key_idx];
            match self.data.get(&addr) {
                Some(route_indices) => {
                    if self.vec_idx + 1 >= route_indices.len() {
                        // we are at the last entry for this vec
                        self.vec_idx = 0;
                        self.key_idx += 1;
                    } else {
                        self.vec_idx += 1;
                    }
                    return Some(
                        *route_indices
                            .get(self.vec_idx)
                            .expect("KeySubsetIterator: data was empty!"),
                    );
                }
                None => {
                    self.key_idx += 1;
                    continue;
                }
            };
        }
        None
    }
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Debug)]
struct RouteEntry {
    start: NodeIndex,
    edges: Vec<EdgeIndex>,
}

impl RouteEntry {
    /// Create a new RouteEntry
    ///
    /// ProtoGraph internal route representation: Represents a route by it's
    /// start token (indicating a direction) as well as by a series of
    /// edge indices.
    ///
    /// Given a starting NodeIndex and a Vec of EdgeIndexes, creates a new
    /// RouteEntry struct.
    ///
    /// # Arguments
    ///
    /// * start - The NodeIndex representing the starting point of the route.
    /// * edges - A Vec of EdgeIndexes representing the edges in the route.
    ///
    /// # Returns
    ///
    /// A new RouteEntry struct.
    fn new(start: NodeIndex, edges: Vec<EdgeIndex>) -> Self {
        RouteEntry { start, edges }
    }
}

pub struct ProtoGraph {
    /// The maximum number of depth for route searches.
    n_hops: usize,
    /// A map of token addresses to their corresponding token and node index in the graph.
    tokens: HashMap<H160, TokenEntry>,
    /// A map of pool addresses to their corresponding pair struct in the graph.
    states: HashMap<H160, Pair>,
    /// The underlying graph data structure.
    graph: UnGraph<H160, H160>,
    /// A cache of all routes with length < n_hops in the graph.
    routes: Vec<RouteEntry>,
    /// A cache of the membership of each address in the graph to routes.
    route_memberships: HashMap<H160, Vec<usize>>,
    /// "workhorse collection" for state overrides
    original_states: HashMap<H160, ProtocolState>,
}

impl ProtoGraph {
    /// Graph of protocols for swap simulations
    ///
    /// A struct that represents a graph of protocols that enable trade simulations. It contains
    /// information about the tokens, states and edges of each pair in the graph.
    pub fn new(n_hops: usize) -> Self {
        ProtoGraph {
            n_hops,
            tokens: HashMap::new(),
            states: HashMap::new(),
            graph: UnGraph::new_undirected(),
            routes: Vec::new(),
            route_memberships: HashMap::new(),
            original_states: HashMap::new(),
        }
    }

    /// Transition states using events
    ///
    /// This method will transition the corresponding states with the given events
    /// inplace. Depending on the ignore_errors the method will either panic on
    /// tranistion errors or simply ignore them.
    pub fn transition_states(
        &mut self,
        events: &[(ProtocolEvent, EVMLogMeta)],
        ignore_errors: bool,
    ) {
        for (ev, logmeta) in events.iter() {
            let address = logmeta.from;
            if let Some(Pair(_, state)) = self.states.get_mut(&address) {
                let res = state.transition(ev, logmeta);
                if !ignore_errors {
                    res.unwrap_or_else(|_| {
                        panic!(
                            "Error transitioning on event {:?} from address {}",
                            ev, address
                        )
                    });
                } else if let Err(err) = res {
                    warn!(
                        "Ignoring transitioning error {:?} for event {:?} from address: {}",
                        err, ev, address
                    );
                }
            } else {
                trace!("Tried to transition on event from address {} which is not in graph! Skipping...", address);
                continue;
            }
        }
    }

    /// Transition states in a revertible manner
    ///
    /// This method will transition states given a collection of events. Previous states are
    /// recorded separately such that the transition can later be reverted using: `rever_states`
    /// This is slower but safer in case transition errors need to handled gracefully or
    /// if the events are not yet fully settled.
    ///
    /// # Note
    ///
    /// This method can only record a single transition so if called multiple times it must be
    /// made sure that `revert_states` was called in between.
    pub fn transition_states_revertibly(
        &mut self,
        events: &[(ProtocolEvent, EVMLogMeta)],
    ) -> Result<(), TransitionError<LogIndex>> {
        if !self.original_states.is_empty() {
            panic!("Original states not cleared!")
        }
        for (ev, logmeta) in events.iter() {
            let address = logmeta.from;
            let old_state;
            if let Some(Pair(_, state)) = self.states.get_mut(&address) {
                old_state = state;
            } else {
                trace!("Tried to transition on event from address {} which is not in graph! Skipping...", address);
                continue;
            };
            // Only save original state the first time in case there are multiple logs for the
            // same pool else revert would not properly work anymore.
            self.original_states
                .entry(address)
                .or_insert_with(|| old_state.clone());
            old_state.transition(ev, logmeta)?;
        }
        Ok(())
    }

    /// Revert states by a single transition
    ///
    /// Allows to revert the states by one transition. Require have called
    /// `transition_states_revertibly` before.
    pub fn revert_states(&mut self) {
        for (address, state) in self.original_states.iter() {
            let pair = self.states.get_mut(address).unwrap();
            pair.1 = state.clone();
        }
        self.original_states.clear();
    }

    /// Applies a closure on temporarily transitioned state
    ///
    /// This method will apply some events to the state, then execute the action function
    /// and finally revert the states again.
    ///
    /// It will return as Result of whatever the action function returned or return
    /// an error if the transtion was not successfull.
    pub fn with_states_transitioned<T, F: Fn(&ProtoGraph) -> T>(
        &mut self,
        events: &[(ProtocolEvent, EVMLogMeta)],
        action: F,
    ) -> Result<T, TransitionError<LogIndex>> {
        self.transition_states_revertibly(events)?;
        let res = action(self);
        self.revert_states();
        Ok(res)
    }

    /// Inserts a trading pair into the graph
    ///
    /// Given a `Pair` struct, it adds missing tokens to the graph and creates edges
    /// between the tokens. It also records the pair in the states.
    ///
    /// # Arguments
    ///
    /// * `Pair(properties, state)` - A `Pair` struct that contains information about the trading pair and its state.
    ///
    /// # Returns
    ///
    /// * `Option<Pair>` - returns the inserted pair, or `None` if it could not be inserted.
    pub fn insert_pair(&mut self, Pair(properties, state): Pair) -> Option<Pair> {
        // add missing tokens to graph
        for token in properties.tokens.iter() {
            if let std::collections::hash_map::Entry::Vacant(e) = self.tokens.entry(token.address) {
                let node_idx = self.graph.add_node(token.address);
                e.insert(TokenEntry(node_idx, token.clone()));
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

    /// Update a pairs state
    ///
    /// Given an address and a new `ProtocolState`, it updates the state
    /// of the pair with that address.
    ///
    /// # Arguments
    ///
    /// * `address` - The address of the pair to update.
    /// * `state` - The new state of the pair.
    ///
    /// # Returns
    ///
    /// * `Option<()>` - returns `Some(())` if the state was updated, or `
    ///     None` if the pair with that address could not be found.
    pub fn update_state(&mut self, address: &H160, state: ProtocolState) -> Option<()> {
        // TODO this should work purely on log updates and the transition
        if let Some(pair) = self.states.get_mut(address) {
            pair.1 = state;
            return Some(());
        }
        None
    }

    /// Builds the internal route cache for the token graph.
    ///
    /// This function should be called whenever the graphs topology changes
    /// such that the `search_opportunities` method can correctly take into
    /// account newly added edges.
    ///
    /// # Arguments
    ///
    /// * `start_token` - The token address to start building the routes from.
    /// * `end_token` - The token address the built routes must end with.
    ///
    /// # Errors
    ///
    /// The function will error if one of the token addresses provided are not present in
    /// the graph's `tokens` map.
    pub fn build_routes(
        &mut self,
        start_token: H160,
        end_token: H160,
    ) -> Result<(), Box<dyn Error>> {
        let start_node_idx = match self.tokens.get(&start_token) {
            Some(&TokenEntry(start_node_idx, _)) => start_node_idx,
            None => {
                return Err(Box::<dyn Error>::from(format!(
                    "Token address {:?} not found",
                    start_token
                )))
            }
        };

        let end_node_idx = match self.tokens.get(&end_token) {
            Some(&TokenEntry(end_node_idx, _)) => end_node_idx,
            None => {
                return Err(Box::<dyn Error>::from(format!(
                    "Token address {:?} not found",
                    end_token
                )))
            }
        };

        let edge_routes = all_edge_routes::<Vec<_>, _>(
            &self.graph,
            start_node_idx,
            end_node_idx,
            1,
            Some(self.n_hops),
        );

        info!("Searching routes...");
        for route in edge_routes {
            // insert route only if it does not yet exist
            let entry = RouteEntry::new(start_node_idx, route);
            if let Err(pos) = self.routes.binary_search(&entry) {
                self.routes.insert(pos, entry);
            };
        }

        info!("Building membership cache...");
        for pos in 0..self.routes.len() {
            // build membership cache
            for edge_idx in self.routes[pos].edges.iter() {
                let addr = *self.graph.edge_weight(*edge_idx).unwrap();
                if let Some(route_indices) = self.route_memberships.get_mut(&addr) {
                    route_indices.push(pos);
                } else {
                    self.route_memberships.insert(addr, vec![pos]);
                }
            }
        }
        self.routes.shrink_to_fit();

        Ok(())
    }

    /// Given a search function, searches the token graph for trading opportunities over its routes.
    ///
    /// # Arguments
    ///
    /// * `search` - A function that takes in a `Route` and returns an `Option<SwapSequence>` representing a trading opportunity if one is found.
    /// * `involved_addresses` - A list of token addresses to filter the routes that are searched on.
    ///
    /// # Returns
    ///
    /// A vector of all potentially profitable SwapSequences found.
    pub fn search_opportunities<F: Fn(Route) -> Option<SwapSequence>>(
        &self,
        search: F,
        involved_addresses: Option<Vec<H160>>,
    ) -> Vec<SwapSequence> {
        // PERF: .unique() allocates a hash map in the background, also pairs and token vectors allocate.
        // This is suboptimal for performance, I decided to leave this here though as it will simplify parallelisation.
        // To optimize this, each worker needs a preallocated collections that are cleared on each invocation.
        let mut pairs = Vec::with_capacity(self.n_hops);
        let mut tokens = Vec::with_capacity(self.n_hops + 1);
        // allocates only if there is an opportunity
        let mut opportunities = Vec::new();
        // RouteIdSubsetsByMembership will return a list of route ids we make sure the route ids are unique and yield the
        // corresponding RouteEntry object. This way we get all routes that contain any of the changed addresses.
        // In case we didn't see some address on any route (KeyError on route_memberhips) it is simply skipped.
        let route_iter =
            RouteIdSubsetsByMembership::new(involved_addresses, &self.route_memberships)
                .unique()
                .map(|idx| &self.routes[idx]);
        let mut n_routes_evaluated: u64 = 0;
        for route in route_iter {
            pairs.clear();
            tokens.clear();
            let mut prev_node_idx = route.start;
            let TokenEntry(_, start) = &self.tokens[self.graph.node_weight(route.start).unwrap()];
            tokens.push(start);
            for edge_idx in route.edges.iter() {
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
                    panic!("Routes node indices did not connect!")
                };
                pairs.push(state);
                tokens.push(next_token);
            }
            let r = Route::new(&tokens, &pairs);
            n_routes_evaluated += 1;
            if let Some(opp) = search(r) {
                opportunities.push(opp);
            }
        }
        debug!("Searched {} route", n_routes_evaluated);
        opportunities
    }

    pub fn info(&self) {
        info!("ProtoGraph(n_hops={}) Stats:", self.n_hops);
        info!("States: {}", self.states.len());
        info!("Nodes: {}", self.tokens.len());
        info!("Routes: {}", self.routes.len());
        info!("Membership Cache: {}", self.route_memberships.len());
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::optimize::gss::golden_section_search;
    use crate::protocol::models::PairProperties;
    use crate::protocol::uniswap_v2::events::UniswapV2Sync;
    use crate::protocol::uniswap_v2::state::UniswapV2State;
    use ethers::types::{Sign, H256, I256};
    use rstest::rstest;

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

    fn construct_graph() -> ProtoGraph {
        let mut g = ProtoGraph::new(2);
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
            20_000_000,
        ));
        g.build_routes(
            H160::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            H160::from_str("0x0000000000000000000000000000000000000001").unwrap(),
        );
        g
    }

    fn logmeta(from: &str, log_idx: LogIndex) -> EVMLogMeta {
        EVMLogMeta {
            from: H160::from_str(from).unwrap(),
            block_number: log_idx.0,
            block_hash: H256::from_str(
                "0x8b1cc9f28716bc7c994db5442dd9bb53b90b73f2f6ef7956fd16ab59ecc6f7ad",
            )
            .unwrap(),
            transaction_index: 1,
            transaction_hash: H256::from_str(
                "0x8a9b8d0cbbace89ea6d8e70f5a1f69a4ae129b11dccd6d13e96eee71a5c0e446",
            )
            .unwrap(),
            log_index: log_idx.1,
        }
    }

    #[test]
    fn test_transition() {
        let mut g = construct_graph();
        let original_states = g.states.clone();
        let addr_changed = H160::from_str("0x0000000000000000000000000000000000000002").unwrap();
        let addr_untouched = H160::from_str("0x0000000000000000000000000000000000000001").unwrap();
        let events = vec![(
            UniswapV2Sync::new(U256::from(20_000_000), U256::from(10_000_000)).into(),
            logmeta("0x0000000000000000000000000000000000000002", (1, 1)),
        )];

        g.transition_states(events.as_slice(), false);

        assert_ne!(g.states[&addr_changed], original_states[&addr_changed]);
        assert_eq!(g.states[&addr_untouched], original_states[&addr_untouched]);
    }

    #[test]
    #[should_panic]
    fn test_transition_err_panic() {
        let mut g = construct_graph();
        let events = vec![(
            UniswapV2Sync::new(U256::from(20_000_000), U256::from(10_000_000)).into(),
            logmeta("0x0000000000000000000000000000000000000002", (0, 0)),
        )];

        g.transition_states(events.as_slice(), false);
    }

    #[test]
    fn test_transition_err_ignore() {
        let mut g = construct_graph();
        let original_states = g.states.clone();
        let events = vec![(
            UniswapV2Sync::new(U256::from(20_000_000), U256::from(10_000_000)).into(),
            logmeta("0x0000000000000000000000000000000000000002", (0, 0)),
        )];

        g.transition_states(events.as_slice(), true);

        assert_eq!(g.states, original_states);
    }

    #[test]
    fn test_transition_revertibly() {
        let mut g = construct_graph();
        let original_states = g.states.clone();
        let events = vec![(
            UniswapV2Sync::new(U256::from(20_000_000), U256::from(10_000_000)).into(),
            logmeta("0x0000000000000000000000000000000000000002", (0, 1)),
        )];

        g.transition_states_revertibly(&events).unwrap();
        assert_ne!(original_states, g.states);

        g.revert_states();
        assert_eq!(original_states, g.states);
    }

    #[test]
    fn test_with_states_transitioned() {
        let mut g = construct_graph();
        let original_states = g.states.clone();
        let events = vec![(
            UniswapV2Sync::new(U256::from(20_000_000), U256::from(10_000_000)).into(),
            logmeta("0x0000000000000000000000000000000000000002", (0, 1)),
        )];

        g.with_states_transitioned(&events, |g| {
            assert_ne!(original_states, g.states);
        })
        .unwrap();

        assert_eq!(original_states, g.states);
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
    fn test_build_routes(#[case] pairs: &[(&str, &str, &str)], #[case] exp: Vec<Vec<&str>>) {
        let mut g = ProtoGraph::new(4);
        let exp: Vec<_> = exp
            .iter()
            .map(|v| {
                v.iter()
                    .map(|s| H160::from_str(s).unwrap())
                    .collect::<Vec<_>>()
            })
            .collect();
        for p in pairs {
            g.insert_pair(make_pair(p.0, p.1, p.2, 2000, 2000));
        }

        g.build_routes(
            H160::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            H160::from_str("0x0000000000000000000000000000000000000001").unwrap(),
        );

        let mut routes = Vec::with_capacity(g.routes.len());
        for r in g.routes {
            let addr_route: Vec<_> = routes
                .edges
                .iter()
                .map(|x| *g.graph.edge_weight(*x).unwrap())
                .collect();
            routes.push(addr_route);
        }
        assert_eq!(routes, exp);
    }

    #[rstest]
    fn test_build_routes_missing_token() {
        let mut g = ProtoGraph::new(4);
        let pairs = [
            (
                "0x0000000000000000000000000000000000000001",
                "0x0000000000000000000000000000000000000001",
                "0x0000000000000000000000000000000000000002",
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
            ),
        ];
        for p in pairs {
            g.insert_pair(make_pair(p.0, p.1, p.2, 2000, 2000));
        }

        let res = g.build_routes(
            H160::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            H160::from_str("0x0000000000000000000000000000000000000004").unwrap(),
        );

        assert!(res.is_err());
        if let Err(error) = res {
            assert_eq!(
                error.to_string(),
                "Token address 0x0000000000000000000000000000000000000004 not found"
            )
        }
    }

    fn atomic_arb_finder(r: Route) -> Option<SwapSequence> {
        let price = r.price();
        if price > 1.0 {
            let amount_in = optimize_route(&r).ok()?;
            if amount_in > U256::zero() {
                let (swaps, gas) = r.get_swaps(amount_in).unwrap();
                let amount_out = swaps[swaps.len() - 1].amount_out();
                if amount_out > amount_in {
                    let opp = SwapSequence::new(swaps, gas);
                    return Some(opp);
                }
                return None;
            }
        }
        None
    }

    fn optimize_route(p: &Route) -> Result<U256, TradeSimulationError> {
        let sim_arb = |amount_in: I256| {
            let amount_in_unsigned = if amount_in > I256::zero() {
                amount_in.into_raw()
            } else {
                U256::zero()
            };

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
            let amount_out =
                I256::checked_from_sign_and_abs(Sign::Positive, amount_out_unsigned).unwrap();
            amount_out - amount_in
        };
        let res = golden_section_search(
            sim_arb,
            U256::one(),
            U256::from(100_000),
            I256::one(),
            100,
            false,
        )?;
        Ok(res.0)
    }

    #[rstest]
    #[case(Some(vec![H160::from_str("0x0000000000000000000000000000000000000001").unwrap()]))]
    #[case(None)]
    fn test_simulate_route(#[case] addresses: Option<Vec<H160>>) {
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
        g.build_routes(
            H160::from_str("0x0000000000000000000000000000000000000001").unwrap(),
            H160::from_str("0x0000000000000000000000000000000000000001").unwrap(),
        );
        let opps = g.search_opportunities(atomic_arb_finder, addresses);

        assert_eq!(opps.len(), 1);
    }

    #[rstest]
    #[case::empty(HashMap::new(), None, vec![])]
    #[case::empty_keys(HashMap::from([(H160::from_low_u64_be(1), vec![1,2]), (H160::from_low_u64_be(2), vec![3,4]),]), Some(vec![]), vec![])]
    #[case::one_key(HashMap::from([(H160::from_low_u64_be(1), vec![1,2]), (H160::from_low_u64_be(2), vec![3,4]),]), Some(vec![H160::from_low_u64_be(2)]), vec![3,4])]
    #[case::one_key(HashMap::from([(H160::from_low_u64_be(1), vec![1,2]), (H160::from_low_u64_be(2), vec![3,4]),]), Some(vec![H160::from_low_u64_be(1)]), vec![1,2])]
    #[case::two_keys(HashMap::from([(H160::from_low_u64_be(1), vec![1]), (H160::from_low_u64_be(2), vec![3,4]),]), Some(vec![H160::from_low_u64_be(1), H160::from_low_u64_be(2)]), vec![1,3,4])]
    fn test_key_subset_iterator(
        #[case] data: HashMap<H160, Vec<usize>>,
        #[case] keys: Option<Vec<H160>>,
        #[case] exp: Vec<usize>,
    ) {
        let it = RouteIdSubsetsByMembership::new(keys, &data);

        let mut res: Vec<_> = it.collect();
        res.sort();

        assert_eq!(res, exp);
    }

    #[test]
    fn test_route_price() {
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
        let Pair(props, _) = &pair_0;
        let tokens = vec![&props.tokens[0], &props.tokens[1], &props.tokens[0]];
        let pairs = vec![&pair_0, &pair_1];
        let route = Route::new(&tokens, &pairs);

        let res = route.price();

        assert_eq!(res, 0.4);
    }

    #[test]
    fn test_get_amount_out() {
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
        let Pair(props, _) = &pair_0;
        let tokens = vec![&props.tokens[0], &props.tokens[1], &props.tokens[0]];
        let pairs = vec![&pair_0, &pair_1];
        let route = Route::new(&tokens, &pairs);

        let res = route.get_amount_out(U256::from(100_000)).unwrap();

        assert_eq!(res.gas, U256::from(240_000));
        assert_eq!(res.amount, U256::from(39_484));
    }

    #[test]
    fn test_get_swaps() {
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
        let Pair(props, _) = &pair_0;
        let tokens = vec![&props.tokens[0], &props.tokens[1], &props.tokens[0]];
        let pairs = vec![&pair_0, &pair_1];
        let route = Route::new(&tokens, &pairs);
        let amount_in = U256::from(100_000);

        let (actions, _) = route.get_swaps(amount_in).unwrap();

        assert_eq!(actions[0].amount_in(), amount_in);
        assert_eq!(actions[0].amount_out(), actions[1].amount_in());
        assert_eq!(actions[1].amount_out(), U256::from(39_484))
    }
}
