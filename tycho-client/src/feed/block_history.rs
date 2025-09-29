use std::{collections::VecDeque, num::NonZeroUsize};

use lru::LruCache;
use thiserror::Error;
use tracing::{debug, error};
use tycho_common::{display::opt, Bytes};

use crate::feed::BlockHeader;

#[derive(Debug, Error)]
pub enum BlockHistoryError {
    #[error("Cache size cannot be 0")]
    InvalidCacheSize,
    #[error("History is empty")]
    EmptyHistory,
    #[error("Could not determine the block's position")]
    UndeterminedBlockPosition,
    #[error("Reverting block's insert position not found! History exceeded")]
    RevertPositionNotFound,
    #[error("Pushing a detached block is unsafe")]
    DetachedBlock,
}

pub struct BlockHistory {
    history: VecDeque<BlockHeader>,
    reverts: LruCache<Bytes, BlockHeader>,
    size: usize,
}

#[derive(Debug, PartialEq)]
pub enum BlockPosition {
    /// The next expected block
    NextExpected,
    /// The latest processed block
    Latest,
    /// A previously seen block
    Delayed,
    /// A detached block with a height above NextExpected
    Advanced,
}

/// BlockHistory
///
/// Provides lightweight validation and relative positioning of received block headers
/// emitted by StateSynchronizer structs.
impl BlockHistory {
    /// Create a new BlockHistory from a vector of headers.
    ///
    /// The latest block and all connected block preceeding it are added to the history.
    /// Detached blocks are skipped.
    pub fn new(mut history: Vec<BlockHeader>, size: usize) -> Result<Self, BlockHistoryError> {
        // sort history by block number in descending order
        history.sort_by_key(|h| h.number);
        history.reverse();

        // Start with the latest block and build connected chain
        let mut connected_chain = Vec::new();
        if let Some(latest) = history.first() {
            connected_chain.push(latest.clone());
            let mut current_hash = latest.parent_hash.clone();
            let mut current_number = latest.number;

            // Find connected blocks in sequence
            for block in history.iter().skip(1) {
                // If we find a gap in block numbers, stop building the chain
                if block.number != current_number - 1 {
                    break;
                }
                // Check hash connection (preceeding block is parent of current block)
                if block.hash == current_hash {
                    connected_chain.push(block.clone());
                    current_hash = block.parent_hash.clone();
                    current_number = block.number;
                }
            }
        }

        // Reverse to get oldest->newest order
        connected_chain.reverse();

        let cache_size = NonZeroUsize::new(size * 10).ok_or(BlockHistoryError::InvalidCacheSize)?;
        debug!(tip = opt(&connected_chain.last()), "InitBlockHistory");
        Ok(Self {
            history: VecDeque::from(connected_chain),
            size,
            reverts: LruCache::new(cache_size),
        })
    }

    /// Add the block as next block.
    ///
    /// May error if the block does not fit the tip of the chain, or if history is empty and the
    /// block is a revert.
    pub fn push(&mut self, block: BlockHeader) -> Result<(), BlockHistoryError> {
        let pos = self.determine_block_position(&block)?;
        match pos {
            BlockPosition::NextExpected => {
                // if the block is NextExpected, but does not fit on top of the latest
                // block (via parent hash) -> we are dealing with a
                // revert.
                if block.revert {
                    // keep removing the head until the new block fits
                    loop {
                        let head = self
                            .history
                            .back()
                            .ok_or(BlockHistoryError::RevertPositionNotFound)?;

                        if head.hash == block.parent_hash {
                            break;
                        } else {
                            let reverted_block = self
                                .history
                                .pop_back()
                                .ok_or(BlockHistoryError::RevertPositionNotFound)?;
                            // record reverted blocks in cache
                            self.reverts
                                .push(reverted_block.hash.clone(), reverted_block);
                        }
                    }
                }
                // Final sanity check against things going awfully wrong.
                if let Some(true) = self
                    .latest()
                    .map(|b| b.hash != block.parent_hash)
                {
                    return Err(BlockHistoryError::DetachedBlock);
                }
                // Push new block to history, marking it as latest.
                debug!(
                    tip = ?block.parent_hash,
                    "BlockHistoryUpdate"
                );
                self.history.push_back(block);
                if self.history.len() > self.size {
                    self.history.pop_front();
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Determines the blocks position relative to current history.
    ///
    /// If there is no history we'll return an error here. This will also error if we
    /// have a single block and we encounter a revert as it will be impossible to
    /// find the fork block.
    pub fn determine_block_position(
        &self,
        block: &BlockHeader,
    ) -> Result<BlockPosition, BlockHistoryError> {
        let latest = self
            .latest()
            .ok_or(BlockHistoryError::EmptyHistory)?;

        Ok(if block.parent_hash == latest.hash {
            // if the block is the next expected block.
            BlockPosition::NextExpected
        } else if (block.hash == latest.hash) & !block.revert {
            // if the block is the latest block and it is not a revert.
            BlockPosition::Latest
        } else if self.reverts.contains(&block.hash) {
            // if the block is still on an already reverted branch.
            BlockPosition::Delayed
        } else if block.number <= latest.number {
            // block is potentially delayed or reverted.

            let oldest = self
                .oldest()
                .ok_or(BlockHistoryError::EmptyHistory)?;

            if block.number < oldest.number {
                // if this block is older than the oldest block in our history it means it is
                // delayed.
                BlockPosition::Delayed
            } else if self.hash_in_history(&block.hash) {
                // if this block is in our history
                if block.revert {
                    // if it is a revert, that is a expected forward update.
                    BlockPosition::NextExpected
                } else {
                    // if this is not a revert it means this block is delayed.
                    BlockPosition::Delayed
                }
            } else {
                // anything else raises e.g. a completely detached, revert=false block
                let history = &self.history;
                let is_revert = block.revert;
                error!(?history, ?block, ?is_revert, "Could not determine history");
                Err(BlockHistoryError::UndeterminedBlockPosition)?
            }
        } else {
            // otherwise the block is advanced.
            BlockPosition::Advanced
        })
    }

    fn hash_in_history(&self, h: &Bytes) -> bool {
        self.history
            .iter()
            .any(|b| &b.hash == h)
    }

    pub fn latest(&self) -> Option<&BlockHeader> {
        self.history.back()
    }

    pub fn oldest(&self) -> Option<&BlockHeader> {
        self.history.front()
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;
    use rstest::rstest;

    use super::*;

    fn random_hash() -> Bytes {
        let mut rng = rand::thread_rng();

        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes[..]);

        Bytes::from(bytes)
    }

    fn int_hash(no: u64) -> Bytes {
        Bytes::from(no.to_be_bytes())
    }

    fn generate_blocks(n: usize, start_n: u64, parent: Option<Bytes>) -> Vec<BlockHeader> {
        let mut blocks = Vec::with_capacity(n);
        let mut parent_hash = parent.unwrap_or_else(random_hash);
        for i in start_n..start_n + n as u64 {
            let hash = int_hash(i);
            blocks.push(BlockHeader {
                number: i,
                hash: hash.clone(),
                parent_hash,
                revert: false,
                ..Default::default()
            });
            parent_hash = hash;
        }
        blocks
    }

    #[test]
    fn test_push() {
        let start_blocks = generate_blocks(1, 0, None);
        let new_block = BlockHeader {
            number: 1,
            hash: random_hash(),
            parent_hash: int_hash(0),
            revert: false,
            ..Default::default()
        };
        let mut history =
            BlockHistory::new(start_blocks.clone(), 2).expect("block history creation failed");

        history
            .push(new_block.clone())
            .expect("push failed");

        let hist = history
            .history
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(hist, vec![start_blocks[0].clone(), new_block]);
    }

    #[test]
    fn test_size_limit() {
        let blocks = generate_blocks(3, 0, None);
        let mut history =
            BlockHistory::new(blocks[0..2].to_vec(), 2).expect("failed to create history");

        history
            .push(blocks[2].clone())
            .expect("push failed");

        assert_eq!(history.history.len(), 2);
    }

    #[test]
    fn test_push_revert_push() {
        let blocks = generate_blocks(5, 0, None);
        let mut history = BlockHistory::new(blocks.clone(), 5).expect("failed to create history");
        let revert_block = BlockHeader {
            number: 2,
            hash: int_hash(2),
            parent_hash: int_hash(1),
            revert: true,
            ..Default::default()
        };
        let new_block = BlockHeader {
            number: 3,
            hash: random_hash(),
            parent_hash: int_hash(2),
            revert: false,
            ..Default::default()
        };
        let mut exp_history: Vec<_> = blocks[0..3]
            .iter()
            .cloned()
            .chain([new_block.clone()])
            .collect();
        exp_history[2].revert = true;

        history
            .push(revert_block.clone())
            .expect("push failed");
        history
            .push(new_block.clone())
            .expect("push failed");

        assert_eq!(history.history, exp_history);
        assert!(history.reverts.contains(&int_hash(3)));
        assert!(history.reverts.contains(&int_hash(4)));
    }

    #[test]
    fn test_push_detached_block() {
        let blocks = generate_blocks(3, 0, None);
        let mut history = BlockHistory::new(blocks.clone(), 5).expect("failed to create history");
        let new_block = BlockHeader {
            number: 2,
            hash: int_hash(2),
            parent_hash: random_hash(),
            revert: true,
            ..Default::default()
        };

        let res = history.push(new_block.clone());

        assert!(res.is_err());
    }

    #[test]
    fn test_new_block_history() {
        // Create a valid chain of 5 blocks starting from block 5
        let mut blocks = generate_blocks(5, 5, None);

        // Add some disconnected blocks
        blocks.push(BlockHeader {
            number: 2, // Gap in block numbers
            hash: random_hash(),
            parent_hash: random_hash(),
            revert: false,
            ..Default::default()
        });
        blocks.push(BlockHeader {
            number: 4,
            hash: random_hash(),
            parent_hash: random_hash(), // Disconnected
            revert: false,
            ..Default::default()
        });

        let history = BlockHistory::new(blocks, 10).expect("failed to create history");

        // Should only contain the original 5 connected blocks
        assert_eq!(history.history.len(), 5);

        // Verify the blocks are in order
        let blocks: Vec<_> = history.history.iter().collect();
        for i in 0..blocks.len() - 1 {
            assert_eq!(blocks[i].number + 1, blocks[i + 1].number);
            assert_eq!(blocks[i].hash, blocks[i + 1].parent_hash);
        }
    }

    #[rstest]
    #[case(BlockHeader { number: 15, hash: int_hash(15), parent_hash: int_hash(14), revert: false,..Default::default() }, BlockPosition::NextExpected)]
    #[case(BlockHeader { number: 14, hash: int_hash(14), parent_hash: int_hash(13), revert: false,..Default::default() }, BlockPosition::Latest)]
    #[case(BlockHeader { number: 16, hash: int_hash(16), parent_hash: int_hash(15), revert: false ,..Default::default()}, BlockPosition::Advanced)]
    #[case(BlockHeader { number: 12, hash: int_hash(12), parent_hash: int_hash(11), revert: false ,..Default::default()}, BlockPosition::Delayed)]
    #[case(BlockHeader { number: 14, hash: int_hash(14), parent_hash: int_hash(13), revert: true ,..Default::default()}, BlockPosition::NextExpected)]
    #[case(BlockHeader { number: 1, hash: int_hash(1), parent_hash: int_hash(0), revert: false ,..Default::default()}, BlockPosition::Delayed)]
    fn test_determine_position(#[case] add_block: BlockHeader, #[case] exp_pos: BlockPosition) {
        let start_blocks = generate_blocks(10, 5, None);
        let history = BlockHistory::new(start_blocks, 20).expect("failed to create history");

        let res = history
            .determine_block_position(&add_block)
            .expect("failed to determine position");

        assert_eq!(res, exp_pos);
    }

    #[test]
    fn test_determine_position_reverted_branch() {
        let start_blocks = generate_blocks(10, 0, None);
        let mut history = BlockHistory::new(start_blocks, 15).expect("failed to create history");
        // revert by 2 blocks, add a new one
        history
            .push(BlockHeader {
                number: 7,
                hash: int_hash(7),
                parent_hash: int_hash(6),
                revert: true,
                ..Default::default()
            })
            .unwrap();
        history
            .push(BlockHeader {
                number: 8,
                hash: random_hash(),
                parent_hash: int_hash(7),
                revert: false,
                ..Default::default()
            })
            .unwrap();
        let add_block = BlockHeader {
            number: 9,
            hash: int_hash(9),
            parent_hash: int_hash(8),
            revert: false,
            ..Default::default()
        };

        let res = history
            .determine_block_position(&add_block)
            .expect("failed to determine position");

        assert_eq!(res, BlockPosition::Delayed);
    }
}
