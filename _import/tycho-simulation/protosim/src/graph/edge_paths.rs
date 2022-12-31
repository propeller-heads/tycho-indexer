use indexmap::IndexSet;
use petgraph::{
    visit::{EdgeCount, EdgeRef, IntoEdgeReferences, IntoEdgesDirected, NodeCount},
    Direction::Outgoing,
};
use std::{
    hash::Hash,
    iter::{from_fn, FromIterator},
};

pub fn all_edge_paths<TargetColl, G>(
    graph: G,
    from: G::NodeId,
    to: G::NodeId,
    min_intermediate_nodes: usize,
    max_intermediate_nodes: Option<usize>,
) -> impl Iterator<Item = TargetColl>
where
    G: EdgeCount + NodeCount,
    G: IntoEdgesDirected + IntoEdgeReferences,
    G::EdgeId: Eq + Hash,
    G::NodeId: Eq + Hash,
    TargetColl: FromIterator<G::EdgeId>,
{
    let max_length = if let Some(l) = max_intermediate_nodes {
        l + 1
    } else {
        graph.node_count() - 1
    };

    let min_length = min_intermediate_nodes + 1;

    let mut visited_nodes: IndexSet<G::NodeId> = IndexSet::from_iter(Some(from));
    let mut visited: IndexSet<G::EdgeId> = IndexSet::new();

    let mut stack = vec![graph.edges_directed(from, Outgoing)];
    from_fn(move || {
        while let Some(edges) = stack.last_mut() {
            if let Some(edge) = edges.next() {
                if visited_nodes.len() < max_length {
                    // handles all paths that are < max_length but >= min length
                    if edge.target() == to && !visited.contains(&edge.id()) {
                        if visited_nodes.len() >= min_length {
                            let path = visited
                                .iter()
                                .cloned()
                                .chain(Some(edge.id()))
                                .collect::<TargetColl>();
                            return Some(path);
                        }
                    } else if !visited_nodes.contains(&edge.target())
                        && !visited.contains(&edge.id())
                    {
                        visited.insert(edge.id());
                        visited_nodes.insert(edge.target());
                        stack.push(graph.edges_directed(edge.target(), Outgoing));
                    }
                } else {
                    // Handles all paths that are == max_length and >= min length
                    // We are about to abort this path, check if remaining edges that still
                    // fulfill visted.len() == max_length, for a path to target
                    if visited_nodes.len() > min_length {
                        for edge in edges.chain(Some(edge)) {
                            if edge.target() == to && !visited.contains(&edge.id()) {
                                let path = visited
                                    .iter()
                                    .cloned()
                                    .chain(Some(edge.id()))
                                    .collect::<TargetColl>();
                                return Some(path);
                            }
                        }
                    }
                    visited.pop();
                    visited_nodes.pop();
                    stack.pop();
                }
            } else {
                visited.pop();
                visited_nodes.pop();
                stack.pop();
            }
        }
        None
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use petgraph::{prelude::UnGraph, visit::NodeIndexable};
    use rstest::rstest;

    #[rstest]
    #[case::empty(&[], 1, 0)]
    #[case::single_pool(&[(0, 1)], 2, 0)]
    #[case::two_pools_two_tokens(&[(0, 1), (0, 1)], 3,  2)]
    #[case::three_pools_three_tokens(&[(0, 1), (0, 2), (1, 2)], 4, 2)]
    #[case::doubled_pool_at_start_token(&[(0, 1), (0, 2), (1, 2), (0, 1)], 4, 6)]
    #[case::doubled_pool_at_start_token(&[(0, 1), (0, 2), (1, 2), (0, 2)], 4,  6)]
    #[case::doubled_pool_not_at_start_token(&[(0, 1), (0, 2), (1, 2), (1, 2)], 4, 4)]
    fn test_all_edge_paths(
        #[case] edges: &[(u32, u32)],
        #[case] length: usize,
        #[case] exp: usize,
    ) {
        let g = UnGraph::<(), i32>::from_edges(edges);
        let node = g.from_index(0);

        let paths: Vec<_> = all_edge_paths::<Vec<_>, _>(&g, node, node, 0, Some(length)).collect();

        assert_eq!(paths.len(), exp)
    }
}
