use std::{collections::VecDeque, num::NonZeroUsize};

use lru::LruCache;
use thiserror::Error;
use tracing::error;
use tycho_common::Bytes;

use crate::feed::Header;

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
    history: VecDeque<Header>,
    reverts: LruCache<Bytes, Header>,
    size: usize,
}

#[derive(Debug, PartialEq)]
pub enum BlockPosition {
    // The next expected block
    NextExpected,
    // The latest processed block
    Latest,
    // A previously seen block
    Delayed,
    // An unknown block with a height above latest
    Advanced,
}

/// BlockHistory
///
/// Provides lightweight validation and relative positioning of received block headers
/// emitted by StateSynchronizer structs.
impl BlockHistory {
    pub fn new(mut history: Vec<Header>, size: usize) -> Result<Self, BlockHistoryError> {
        // sort history by block number
        history.sort_by_key(|h| h.number);
        let cache_size = NonZeroUsize::new(size * 10).ok_or(BlockHistoryError::InvalidCacheSize)?;

        Ok(Self { history: VecDeque::from(history), size, reverts: LruCache::new(cache_size) })
    }

    /// Add the block as next block.
    ///
    /// May error if the block does not fit the tip of the chain, or if history is empty and the
    /// block is a revert.
    pub fn push(&mut self, block: Header) -> Result<(), BlockHistoryError> {
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
        block: &Header,
    ) -> Result<BlockPosition, BlockHistoryError> {
        let latest = self
            .latest()
            .ok_or(BlockHistoryError::EmptyHistory)?;
        Ok(if block.parent_hash == latest.hash {
            BlockPosition::NextExpected
        } else if (block.hash == latest.hash) & !block.revert {
            BlockPosition::Latest
        } else if self.reverts.contains(&block.hash) {
            // in this case the block is still on an already reverted branch.
            BlockPosition::Delayed
        } else if block.number <= latest.number {
            // if this block is potentially delayed we have seen it's hash before.
            if block.revert & self.hash_in_history(&block.hash) {
                // if it is a revert, that is a expected forward update.
                BlockPosition::NextExpected
            } else if self.hash_in_history(&block.hash) {
                // if this is not a revert it means this block is delayed.
                BlockPosition::Delayed
            } else {
                // anything else raises e.g. a completely detached, revert=false block
                let history = &self.history;
                let is_revert = block.revert;
                error!(?history, ?block, ?is_revert, "Could not determine history");
                Err(BlockHistoryError::UndeterminedBlockPosition)?
            }
        } else {
            BlockPosition::Advanced
        })
    }

    fn hash_in_history(&self, h: &Bytes) -> bool {
        self.history
            .iter()
            .any(|b| &b.hash == h)
    }

    pub fn latest(&self) -> Option<&Header> {
        self.history.back()
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

    fn generate_blocks(n: usize, parent: Option<Bytes>) -> Vec<Header> {
        let mut blocks = Vec::with_capacity(n);
        let mut parent_hash = parent.unwrap_or_else(random_hash);
        for i in 0..n {
            let hash = int_hash(i as u64);
            blocks.push(Header {
                number: i as u64,
                hash: hash.clone(),
                parent_hash,
                revert: false,
            });
            parent_hash = hash;
        }
        blocks
    }

    #[test]
    fn test_push() {
        let start_blocks = generate_blocks(1, None);
        let new_block =
            Header { number: 1, hash: random_hash(), parent_hash: int_hash(0), revert: false };
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
        let blocks = generate_blocks(3, None);
        let mut history =
            BlockHistory::new(blocks[0..2].to_vec(), 2).expect("failed to create history");

        history
            .push(blocks[2].clone())
            .expect("push failed");

        assert_eq!(history.history.len(), 2);
    }

    #[test]
    fn test_push_revert_push() {
        let blocks = generate_blocks(5, None);
        let mut history = BlockHistory::new(blocks.clone(), 5).expect("failed to create history");
        let revert_block =
            Header { number: 2, hash: int_hash(2), parent_hash: int_hash(1), revert: true };
        let new_block =
            Header { number: 3, hash: random_hash(), parent_hash: int_hash(2), revert: false };
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
        let blocks = generate_blocks(3, None);
        let mut history = BlockHistory::new(blocks.clone(), 5).expect("failed to create history");
        let new_block =
            Header { number: 2, hash: int_hash(2), parent_hash: random_hash(), revert: true };

        let res = history.push(new_block.clone());

        assert!(res.is_err());
    }

    #[rstest]
    #[case(Header { number: 10, hash: random_hash(), parent_hash: int_hash(9), revert: false }, BlockPosition::NextExpected)]
    #[case(Header { number: 9, hash: int_hash(9), parent_hash: int_hash(8), revert: false }, BlockPosition::Latest)]
    #[case(Header { number: 11, hash: int_hash(11), parent_hash: int_hash(10), revert: false }, BlockPosition::Advanced)]
    #[case(Header { number: 7, hash: int_hash(7), parent_hash: int_hash(6), revert: false }, BlockPosition::Delayed)]
    #[case(Header { number: 9, hash: int_hash(9), parent_hash: int_hash(8), revert: true }, BlockPosition::NextExpected)]
    fn test_determine_position(#[case] add_block: Header, #[case] exp_pos: BlockPosition) {
        let start_blocks = generate_blocks(10, None);
        let history = BlockHistory::new(start_blocks, 15).expect("failed to create history");

        let res = history
            .determine_block_position(&add_block)
            .expect("failed to determine position");

        assert_eq!(res, exp_pos);
    }

    #[rstest]
    #[case(Header { number: 9, hash: int_hash(9), parent_hash: int_hash(8), revert: false })]
    fn test_determine_position_reverted_branch(#[case] add_block: Header) {
        let start_blocks = generate_blocks(10, None);
        let mut history = BlockHistory::new(start_blocks, 15).expect("failed to create history");
        // revert by 2 blocks, add a new one
        history
            .push(Header { number: 7, hash: int_hash(7), parent_hash: int_hash(6), revert: true })
            .unwrap();
        history
            .push(Header {
                number: 8,
                hash: random_hash(),
                parent_hash: int_hash(7),
                revert: false,
            })
            .unwrap();

        let res = history
            .determine_block_position(&add_block)
            .expect("failed to determine position");

        assert_eq!(res, BlockPosition::Delayed);
    }
}
