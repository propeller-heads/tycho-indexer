use crate::{models::ERC20Token, protocol::state::ProtocolSim};
use ethers::types::{H160};
use petgraph::{
    graph::{EdgeIndex, NodeIndex},
    visit::EdgeRef,
    Graph,
};
use std::collections::HashMap;
use tracing::debug;

/// Struct to manage graph with updatable nodes and edges
pub struct PoolGraph {
    graph: Graph<ERC20Token, Box<dyn ProtocolSim>, petgraph::Undirected>, /* Bi-directional and
                                                                           * supports multiple
                                                                           * edges */
    node_indices: HashMap<H160, NodeIndex>, // Node indices based on token address
    edge_indices: HashMap<H160, EdgeIndex>, // Edge indices based on pool H160 identifier
}

impl PoolGraph {
    /// Initialize a new PoolGraph
    pub fn new() -> Self {
        Self {
            graph: Graph::new_undirected(),
            node_indices: HashMap::new(),
            edge_indices: HashMap::new(),
        }
    }

    /// Add a pool to the graph with a unique H160 identifier
    pub fn add_pool(
        &mut self,
        token0: ERC20Token,
        token1: ERC20Token,
        pool_id: H160,
        state: Box<dyn ProtocolSim>,
    ) {
        let index0 = self.get_or_add_node(token0);
        let index1 = self.get_or_add_node(token1);

        // Add the pool edge with the unique H160 identifier
        let edge_index = self
            .graph
            .add_edge(index0, index1, state);
        self.edge_indices
            .insert(pool_id, edge_index);
    }

    /// Update an existing pool's reserves using the unique H160 pool identifier
    pub fn update_pool(&mut self, pool_id: H160, new_state: Box<dyn ProtocolSim>) {
        if let Some(&edge_index) = self.edge_indices.get(&pool_id) {
            if let Some(edge_weight) = self.graph.edge_weight_mut(edge_index) {
                *edge_weight = new_state; // Update the pool state with new reserves
            }
            debug!("Updated pool with ID {:?}", pool_id);
        } else {
            debug!("Pool with ID {:?} does not exist", pool_id);
        }
    }

    /// Remove a pool from the graph using the unique H160 pool identifier
    pub fn remove_pool(&mut self, pool_id: H160) {
        if let Some(edge_index) = self.edge_indices.remove(&pool_id) {
            self.graph.remove_edge(edge_index);
        } else {
            debug!("Pool with ID {:?} does not exist", pool_id);
        }
    }

    /// Get or add a node for a token and return its index
    fn get_or_add_node(&mut self, token: ERC20Token) -> NodeIndex {
        if let Some(&index) = self.node_indices.get(&token.address) {
            index
        } else {
            let index = self.graph.add_node(token.clone());
            self.node_indices
                .insert(token.address, index);
            index
        }
    }

    /// Find all paths between two tokens up to a specified maximum depth.
    ///
    /// # Arguments
    ///
    /// * `token0` - The start token.
    /// * `token1` - The target token.
    /// * `max_depth` - The maximum depth/hops to search for paths (must be >= 1).
    ///
    /// # Returns
    ///
    /// `Vec<Vec<(H160, Box<dyn ProtocolSim>)>>` - A vector of paths, where each path is a vector of
    /// tuples. Each tuple contains the `H160` pool ID and the corresponding `ProtocolSim` state
    /// for that edge.
    pub fn find_paths(
        &self,
        token0: &ERC20Token,
        token1: &ERC20Token,
        max_depth: usize,
    ) -> Vec<Vec<(H160, Box<dyn ProtocolSim>)>> {
        if max_depth == 0 {
            return Vec::new();
        }

        // Get the NodeIndex for each token; if either is missing, return an empty list
        let start_index = match self.node_indices.get(&token0.address) {
            Some(&index) => index,
            None => return Vec::new(),
        };

        let target_index = match self.node_indices.get(&token1.address) {
            Some(&index) => index,
            None => return Vec::new(),
        };

        let mut all_paths = Vec::new();

        // Helper function to find the pool ID for an edge
        let get_pool_id = |edge_id| {
            self.edge_indices
                .iter()
                .find(|(_, &idx)| idx == edge_id)
                .map(|(&id, _)| id)
        };

        // Function to recursively find paths
        fn find_paths_recursive(
            graph: &Graph<ERC20Token, Box<dyn ProtocolSim>, petgraph::Undirected>,
            current_index: NodeIndex,
            target_index: NodeIndex,
            current_path: Vec<EdgeIndex>,
            max_depth: usize,
            all_paths: &mut Vec<Vec<EdgeIndex>>,
            visited: &mut Vec<NodeIndex>,
        ) {
            if current_path.len() >= max_depth {
                return;
            }

            visited.push(current_index);

            for edge in graph.edges(current_index) {
                let next_index = edge.target();

                // Skip if we've visited this node already
                if visited.contains(&next_index) {
                    continue;
                }

                let mut new_path = current_path.clone();
                new_path.push(edge.id());

                if next_index == target_index {
                    all_paths.push(new_path);
                } else {
                    find_paths_recursive(
                        graph,
                        next_index,
                        target_index,
                        new_path,
                        max_depth,
                        all_paths,
                        visited,
                    );
                }
            }

            visited.pop();
        }

        // Find all paths using recursive helper
        let mut edge_paths = Vec::new();
        let mut visited = Vec::new();
        find_paths_recursive(
            &self.graph,
            start_index,
            target_index,
            Vec::new(),
            max_depth,
            &mut edge_paths,
            &mut visited,
        );

        // Convert edge paths to the required format
        for edge_path in edge_paths {
            let mut path = Vec::new();
            for edge_index in edge_path {
                if let Some(edge) = self
                    .graph
                    .edge_references()
                    .find(|e| e.id() == edge_index)
                {
                    if let Some(pool_id) = get_pool_id(edge_index) {
                        path.push((pool_id, edge.weight().clone_box()));
                    }
                }
            }
            if !path.is_empty() {
                all_paths.push(path);
            }
        }

        all_paths
    }

    /// Get the two tokens connected by an edge, given its unique H160 identifier.
    ///
    /// # Arguments
    ///
    /// * `pool_id` - The unique H160 identifier of the pool.
    ///
    /// # Returns
    ///
    /// `Option<(ERC20Token, ERC20Token)>` - A tuple containing the two `ERC20Token`s connected by
    /// the edge if it exists, or `None` if the edge does not exist.
    pub fn get_nodes_of_edge(&self, pool_id: H160) -> Option<(ERC20Token, ERC20Token)> {
        // Retrieve the EdgeIndex for the given pool_id
        let edge_index = self.edge_indices.get(&pool_id)?;

        // Get the endpoints (NodeIndex values) of the edge
        let (node_index0, node_index1) = self.graph.edge_endpoints(*edge_index)?;

        // Retrieve the actual tokens from the nodes
        let token0 = self
            .graph
            .node_weight(node_index0)?
            .clone();
        let token1 = self
            .graph
            .node_weight(node_index1)?
            .clone();

        Some((token0, token1))
    }
}
