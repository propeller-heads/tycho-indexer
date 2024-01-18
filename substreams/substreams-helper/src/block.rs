use std::ops::Add;
use std::ops::Mul;

use ethabi::ethereum_types::Address;
use substreams::scalar::BigInt;
use substreams_ethereum::pb::eth::v2::balance_change::Reason;
use substreams_ethereum::pb::eth::v2::{self as eth, BalanceChange};

use crate::convert::BigIntDeserializeExt;
use crate::convert::BigIntSerializeExt;
use crate::math::get_balance_gain;
use crate::utils::{get_latest_day, get_latest_hour};

pub struct BlockIssuance {
    /// Rewards issued for including uncles.
    pub uncle_rewards: BigInt,
    /// Rewards issued for mining the block.
    pub block_rewards: BigInt,
    /// Sum of uncles and block rewards.
    pub sum: BigInt,
}

pub struct BlockHandler<'a>(&'a eth::Block);

impl<'a> BlockHandler<'a> {
    pub fn new(block: &'a eth::Block) -> Self {
        Self(block)
    }

    pub fn hash(&self) -> Vec<u8> {
        self.0.hash.clone()
    }

    pub fn block_number(&self) -> u64 {
        self.0.number
    }

    /// Returns the timestamp for the start of the most recent day
    pub fn timestamp(&self) -> i64 {
        if let Some(header) = self.0.header.as_ref() {
            if let Some(timestamp) = header.timestamp.as_ref() {
                timestamp.seconds
            } else {
                panic!(
                    "Unable to find timestamp in block header!\nBlock: {:?}",
                    self.0
                );
            }
        } else {
            panic!("Unable to find header in block!\nBlock: {:?}", self.0);
        }
    }

    /// Returns the timestamp for the start of the most recent day
    pub fn days_timestamp(&self) -> i64 {
        get_latest_day(self.timestamp())
    }

    /// Returns the timestamp for the start of the most recent hour
    pub fn hours_timestamp(&self) -> i64 {
        get_latest_hour(self.timestamp())
    }

    pub fn author(&self) -> Option<String> {
        if let Some(header) = self.0.header.as_ref() {
            Some(Address::from_slice(&header.coinbase).to_string())
        } else {
            None
        }
    }

    pub fn block_size(&self) -> BigInt {
        BigInt::from(self.0.size)
    }

    /// Get the supply for the current block
    pub fn supply(&self) -> BigInt {
        self.0
            .balance_changes
            .iter()
            .map(|balance_change| {
                // Only need to consider positive movements of balance change as the negative movements
                // are just from the other side of the positive balance changes
                get_balance_gain(balance_change)
            })
            .fold(BigInt::zero(), |sum, val| sum + val)
    }

    /// Gets the number of transactions seen in the block
    pub fn transactions(&self) -> BigInt {
        BigInt::from(self.0.transaction_traces.len() as u64)
    }

    pub fn difficulty(&self) -> BigInt {
        if let Some(header) = self.0.header.as_ref() {
            if let Some(difficulty) = header.difficulty.as_ref() {
                return difficulty.deserialize();
            }
        }
        BigInt::zero()
    }

    pub fn gas_used(&self) -> BigInt {
        if let Some(header) = self.0.header.as_ref() {
            BigInt::from(header.gas_used)
        } else {
            BigInt::zero()
        }
    }

    pub fn gas_limit(&self) -> BigInt {
        if let Some(header) = self.0.header.as_ref() {
            BigInt::from(header.gas_limit)
        } else {
            BigInt::zero()
        }
    }

    pub fn gas_price(&self) -> BigInt {
        if let Some(header) = self.0.header.as_ref() {
            if let Some(base_fee_per_gas) = header.base_fee_per_gas.as_ref() {
                return base_fee_per_gas.deserialize() * self.gas_used();
            }
        }

        BigInt::zero()
    }

    /// Fees burnt in this block.
    pub fn burnt_fees(&self) -> BigInt {
        let header = match self.0.header {
            Some(ref header) => header,
            None => return BigInt::zero(),
        };

        // ETH burns the base fee (only after eip1559, before that base_fee_per_gas will be None).
        // So burn per block = base fee = baseFeePerGas * gasUsed.
        header
            .base_fee_per_gas
            .as_ref()
            .unwrap_or(&BigInt::zero().serialize())
            .deserialize()
            .mul(BigInt::from(header.gas_used))
    }

    pub fn rewards(&self) -> BigInt {
        self.0
            .balance_changes
            .iter()
            .map(|balance_change| {
                if is_a_reward(balance_change) {
                    // We should only be accounting for rewards from one side of the transfer so we will not count negative
                    // balance changes with the idea that there will be a counterpart balance change equivalent to this for
                    // the gain in balance for the rewardee, and we will be counting that one instead
                    get_balance_gain(balance_change)
                } else {
                    BigInt::zero()
                }
            })
            .fold(BigInt::zero(), |sum, val| sum + val)
    }

    /// Returns the detail of newly issued eth, broken down by type, and its total.
    pub fn issuance(&self) -> BlockIssuance {
        let mut issuance = BlockIssuance {
            uncle_rewards: BigInt::zero(),
            block_rewards: BigInt::zero(),
            sum: BigInt::zero(),
        };
        for change in self.0.balance_changes.iter() {
            match Reason::from_i32(change.reason).unwrap_or_default() {
                Reason::RewardMineUncle => {
                    issuance.uncle_rewards = issuance.uncle_rewards.add(get_balance_gain(&change));
                }
                Reason::RewardMineBlock => {
                    issuance.block_rewards = issuance.block_rewards.add(get_balance_gain(&change));
                }
                _ => {}
            }
        }
        return issuance;
    }
}

fn is_a_reward(balance_change: &BalanceChange) -> bool {
    const REWARD_REASONS: [i32; 4] = [
        Reason::RewardFeeReset as i32,
        Reason::RewardMineBlock as i32,
        Reason::RewardMineUncle as i32,
        Reason::RewardTransactionFee as i32,
    ];

    REWARD_REASONS.contains(&balance_change.reason)
}
