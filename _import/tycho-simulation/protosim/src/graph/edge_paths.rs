//! Path finding algorithm
//!
//! This module works on edges instead of nodes to provide better support for MultiGraphs which
//! can have parallel edges between two nodes.
use indexmap::IndexSet;
use petgraph::{
    visit::{EdgeCount, EdgeRef, IntoEdgeReferences, IntoEdgesDirected, NodeCount},
    Direction::Outgoing,
};
use std::{
    hash::Hash,
    iter::{from_fn, FromIterator},
};

/// Returns an iterator of edge ids over paths between two nodes in a graph.
///
///  The returned paths are represented as collections of the type specified by
///  the `TargetColl` type parameter.
///
///  ## Arguments
///
///  - `graph`: The graph to search in. Must implement the `EdgeCount`,
///  `IntoEdgesDirected`, and `IntoEdgeReferences` traits, as well as have `NodeId`
///  and `EdgeId` types that implement `Eq` and `Hash`.
///  - `from`: The starting node of the paths.
///  - `to`: The target node of the paths.
///  - `min_edges`: The minimum number of edges that a path must have to be included
///  in the returned iterator.
///  - `max_edges`: The maximum number of edges that a path can have to be included
///  in the returned iterator. If not specified, defaults to the number of nodes in
///  the graph minus one.
///
///  ## Return
///
///  An iterator over collections of `TargetColl`.
///
///  ## Panics
///
///  Panics if `from` or `to` are not present in the graph.
pub fn all_edge_paths<TargetColl, G>(
    graph: G,
    from: G::NodeId,
    to: G::NodeId,
    min_edges: usize,
    max_edges: Option<usize>,
) -> impl Iterator<Item = TargetColl>
where
    G: EdgeCount + NodeCount,
    G: IntoEdgesDirected + IntoEdgeReferences,
    G::EdgeId: Eq + Hash,
    G::NodeId: Eq + Hash,
    TargetColl: FromIterator<G::EdgeId>,
{
    let max_length = if let Some(l) = max_edges {
        l
    } else {
        graph.node_count() - 1
    };

    let min_length = min_edges;

    let mut visited_nodes: IndexSet<G::NodeId> = IndexSet::from_iter(Some(from));
    // python version has as first element the start
    // node so that is why we add +1 to the length
    let mut visited: IndexSet<G::EdgeId> = IndexSet::new();

    let mut stack = vec![graph.edges_directed(from, Outgoing)];
    from_fn(move || {
        while let Some(edges) = stack.last_mut() {
            if let Some(edge) = edges.next() {
                if visited.len() + 1 < max_length {
                    // handles all paths that are < max_length but >= min length
                    if edge.target() == to && !visited.contains(&edge.id()) {
                        if visited.len() + 1 >= min_length {
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
                    if visited.len() + 1 >= min_length {
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
    use petgraph::{
        prelude::UnGraph,
        visit::{EdgeIndexable, NodeIndexable},
    };
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
        let node = NodeIndexable::from_index(&g, 0);

        assert_eq!(
            all_edge_paths::<Vec<_>, _>(&g, node, node, 0, Some(length)).count(),
            exp
        )
    }

    #[rstest]
    #[case(1, vec![vec![2]])]
    #[case(2, vec![vec![0, 1], vec![2]])]
    #[case(3, vec![vec![0, 1], vec![2], vec![3, 4, 1]])]
    #[case(5, vec![vec![0, 1], vec![2], vec![3, 4, 1]])]
    fn test_all_edge_paths_intermediate_nodes(#[case] l: usize, #[case] paths: Vec<Vec<usize>>) {
        let g = UnGraph::<(), i32>::from_edges(&[(0, 1), (1, 2), (0, 2), (0, 3), (3, 1)]);
        let s = NodeIndexable::from_index(&g, 0);
        let e = NodeIndexable::from_index(&g, 2);
        let exp = paths
            .iter()
            .map(|sub| {
                sub.iter()
                    .map(|i| EdgeIndexable::from_index(&g, *i))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let mut paths: Vec<_> = all_edge_paths::<Vec<_>, _>(&g, s, e, 1, Some(l)).collect();
        paths.sort();

        assert_eq!(paths, exp)
    }
}
