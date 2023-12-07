pub mod ambient;
pub mod storage;
mod utils;

use crate::{
    models::{Chain, ExtractorIdentity, NormalisedMessage, ProtocolSystem},
    storage::{ChangeType, StateGatewayType},
};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    ops::Deref,
};
use tracing::warn;
use utils::{pad_and_parse_32bytes, pad_and_parse_h160};

use crate::pb::tycho::evm::v1 as substreams;
use chrono::NaiveDateTime;
use ethers::{
    types::{H160, H256, U256},
    utils::keccak256,
};
use serde::{Deserialize, Serialize};

use super::ExtractionError;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ProtocolComponent {
    id: Vec<u8>,
    protocol_type_name: String,
    protocol_system: ProtocolSystem,
    tokens: Vec<H160>,
    chain: Chain,
    contracts: Vec<H160>,
    attributes: Option<serde_json::Value>,
    tvl: HashMap<H160, f64>,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ERC20Token {
    chain: Chain,
    address: H160,
    symbol: String,
    decimals: u8,
    // evm specific attributes
    attributes: TokenAttributes,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct TokenAttributes {
    tax: Option<TransferTax>,
    transfer_cost: [u32; 4],
    balance_slot: U256,
    allowance_slot: U256,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
pub enum TransferTax {
    FixedRate(U256),
    FixedAmount(U256),
    Unkown,
}

#[derive(Debug, PartialEq, Copy, Clone, Deserialize, Serialize, Default)]
pub struct Block {
    pub number: u64,
    pub hash: H256,
    pub parent_hash: H256,
    pub chain: Chain,
    pub ts: NaiveDateTime,
}

#[derive(Debug, PartialEq, Copy, Clone, Default)]
pub struct Transaction {
    pub hash: H256,
    pub block_hash: H256,
    pub from: H160,
    pub to: Option<H160>,
    pub index: u64,
}

impl Transaction {
    pub fn new(hash: H256, block_hash: H256, from: H160, to: Option<H160>, index: u64) -> Self {
        Transaction { hash, block_hash, from, to, index }
    }
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub chain: Chain,
    pub address: H160,
    pub title: String,
    pub slots: HashMap<U256, U256>,
    pub balance: U256,
    pub code: Vec<u8>,
    pub code_hash: H256,
    pub balance_modify_tx: H256,
    pub code_modify_tx: H256,
    pub creation_tx: Option<H256>,
}

impl Account {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain: Chain,
        address: H160,
        title: String,
        slots: HashMap<U256, U256>,
        balance: U256,
        code: Vec<u8>,
        code_hash: H256,
        balance_modify_tx: H256,
        code_modify_tx: H256,
        creation_tx: Option<H256>,
    ) -> Self {
        Self {
            chain,
            address,
            title,
            slots,
            balance,
            code,
            code_hash,
            balance_modify_tx,
            code_modify_tx,
            creation_tx,
        }
    }

    #[cfg(test)]
    pub fn set_balance(&mut self, new_balance: U256, modified_at: H256) {
        self.balance = new_balance;
        self.balance_modify_tx = modified_at;
    }
}

impl From<&AccountUpdateWithTx> for Account {
    /// Creates a full account from a change.
    ///
    /// This can be used to get an insertable an account if we know the update
    /// is actually a creation.
    ///
    /// Assumes that all relevant changes are set on `self` if something is
    /// missing, it will use the corresponding types default.
    /// Will use the associated transaction as creation, balance and code modify
    /// transaction.
    fn from(value: &AccountUpdateWithTx) -> Self {
        let empty_hash = H256::from(keccak256(Vec::new()));
        if value.change != ChangeType::Creation {
            warn!("Creating an account from a partial change!")
        }
        Account::new(
            value.chain,
            value.address,
            format!("{:#020x}", value.address),
            value.slots.clone(),
            value.balance.unwrap_or_default(),
            value.code.clone().unwrap_or_default(),
            value
                .code
                .as_ref()
                .map(|v| H256::from(keccak256(v)))
                .unwrap_or(empty_hash),
            value.tx.hash,
            value.tx.hash,
            Some(value.tx.hash),
        )
    }
}

#[derive(PartialEq, Serialize, Deserialize, Clone, Debug)]
pub struct AccountUpdate {
    pub address: H160,
    pub chain: Chain,
    pub slots: HashMap<U256, U256>,
    pub balance: Option<U256>,
    pub code: Option<Vec<u8>>,
    pub change: ChangeType,
}

impl AccountUpdate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: H160,
        chain: Chain,
        slots: HashMap<U256, U256>,
        balance: Option<U256>,
        code: Option<Vec<u8>>,
        change: ChangeType,
    ) -> Self {
        Self { address, chain, slots, balance, code, change }
    }

    /// Merge this update (`self`) with another one (`other`)
    ///
    /// This function is utilized for aggregating multiple updates into a single
    /// update. The attribute values of `other` are set on `self`.
    /// Meanwhile, contract storage maps are merged, in which keys from `other`
    /// take precedence.
    ///
    /// Be noted that, this function will mutate the state of the calling
    /// struct. An error will occur if merging updates from different accounts.
    ///
    /// There are no further validation checks within this method, hence it
    /// could be used as needed. However, you should give preference to
    /// utilizing [AccountUpdateWithTx] for merging, when possible.
    ///
    /// # Errors
    ///
    /// It returns an `ExtractionError::Unknown` error if `self.address` and
    /// `other.address` are not identical.
    ///
    /// # Arguments
    ///
    /// * `other`: An instance of `AccountUpdate`. The attribute values and keys
    /// of `other` will overwrite those of `self`.
    fn merge(&mut self, other: AccountUpdate) -> Result<(), ExtractionError> {
        if self.address != other.address {
            return Err(ExtractionError::Unknown(format!(
                "Can't merge AccountUpdates from differing identities; Expected {:#020x}, got {:#020x}",
                self.address, other.address
            )))
        }

        self.slots.extend(other.slots);

        self.balance = other.balance.or(self.balance);
        self.code = other.code.or(self.code.take());

        Ok(())
    }

    fn is_update(&self) -> bool {
        self.change == ChangeType::Update
    }

    fn is_creation(&self) -> bool {
        self.change == ChangeType::Creation
    }
}

/// A container for account updates grouped by account.
///
/// Hold a single update per account. This is a condensed from of
/// [BlockStateChanges].
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Default)]
pub struct BlockAccountChanges {
    extractor: String,
    chain: Chain,
    pub block: Block,
    pub account_updates: HashMap<H160, AccountUpdate>,
    // any new components are emitted here
    pub new_components: HashMap<H160, ProtocolComponent>,
    // tvl changes by protocol component id
    // Note: components are identifies by chain, system and id
    //  the keys here only contain id. Chain is available on the struct and system,
    //  is inferred by the extraction context (1 or more extractors per system -
    //  never 1 extractor for many systems)
    pub tvl_change: HashMap<String, TvlChange>,
}

impl BlockAccountChanges {
    pub fn new(
        extractor: &str,
        chain: Chain,
        block: Block,
        account_updates: HashMap<H160, AccountUpdate>,
    ) -> Self {
        BlockAccountChanges {
            extractor: extractor.to_owned(),
            chain,
            block,
            account_updates,
            new_components: HashMap::new(),
            tvl_change: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct TvlChange {
    token: H160,
    new_balance: U256,
    // tx where the this balance was observed
    tx: H256,
}

impl TvlChange {
    pub fn try_from_message(
        msg: substreams::TvlUpdate,
        tx: &Transaction,
    ) -> Result<Self, ExtractionError> {
        return Ok(Self {
            token: pad_and_parse_h160(&msg.token).map_err(ExtractionError::DecodeError)?,
            new_balance: pad_and_parse_32bytes::<U256>(&msg.balance)
                .map_err(ExtractionError::DecodeError)?,
            tx: tx.hash,
        });
    }
}

impl NormalisedMessage for BlockAccountChanges {
    fn source(&self) -> ExtractorIdentity {
        ExtractorIdentity::new(self.chain, &self.extractor)
    }
}

/// Updates grouped by their respective transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct AccountUpdateWithTx {
    // TODO: for ambient it works to have only a single update here but long
    // term we need to be able to store changes to multiple accounts per
    // transactions.
    pub update: AccountUpdate,
    pub tx: Transaction,
}

impl AccountUpdateWithTx {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: H160,
        chain: Chain,
        slots: HashMap<U256, U256>,
        balance: Option<U256>,
        code: Option<Vec<u8>>,
        change: ChangeType,
        tx: Transaction,
    ) -> Self {
        Self { update: AccountUpdate { address, chain, slots, balance, code, change }, tx }
    }

    /// Merges this update with another one.
    ///
    /// The method combines two `AccountUpdateWithTx` instances under certain
    /// conditions:
    /// - The block from which both updates came should be the same. If the updates are from
    ///   different blocks, the method will return an error.
    /// - The transactions for each of the updates should be distinct. If they come from the same
    ///   transaction, the method will return an error.
    /// - The order of the transaction matters. The transaction from `other` must have occurred
    ///   later than the self transaction. If the self transaction has a higher index than `other`,
    ///   the method will return an error.
    ///
    /// The merged update keeps the transaction of `other`.
    ///
    /// # Errors
    /// This method will return `ExtractionError::Unknown` if any of the above
    /// conditions is violated.
    pub fn merge(&mut self, other: AccountUpdateWithTx) -> Result<(), ExtractionError> {
        if self.tx.block_hash != other.tx.block_hash {
            return Err(ExtractionError::Unknown(format!(
                "Can't merge AccountUpdates from different blocks: 0x{:x} != 0x{:x}",
                self.tx.block_hash, other.tx.block_hash,
            )))
        }
        if self.tx.hash == other.tx.hash {
            return Err(ExtractionError::Unknown(format!(
                "Can't merge AccountUpdates from the same transaction: 0x{:x}",
                self.tx.hash
            )))
        }
        if self.tx.index > other.tx.index {
            return Err(ExtractionError::Unknown(format!(
                "Can't merge AccountUpdates with lower transaction index: {} > {}",
                self.tx.index, other.tx.index
            )))
        }
        self.tx = other.tx;
        self.update.merge(other.update)
    }
}

impl Deref for AccountUpdateWithTx {
    type Target = AccountUpdate;

    fn deref(&self) -> &Self::Target {
        &self.update
    }
}

/// A container for account updates grouped by transaction.
///
/// Hold the detailed state changes for a block alongside with protocol
/// component changes.
#[derive(Debug, PartialEq)]
pub struct BlockStateChanges {
    extractor: String,
    chain: Chain,
    pub block: Block,
    pub tx_updates: Vec<AccountUpdateWithTx>,
    // TODO: we need to correlate the new components with a tx
    pub new_pools: HashMap<H160, ProtocolComponent>,
}

pub type EVMStateGateway<DB> = StateGatewayType<DB, Block, Transaction, Account, AccountUpdate>;

impl Block {
    /// Parses block from tychos protobuf block message
    pub fn try_from_message(msg: substreams::Block, chain: Chain) -> Result<Self, ExtractionError> {
        Ok(Self {
            chain,
            number: msg.number,
            hash: pad_and_parse_32bytes(&msg.hash).map_err(ExtractionError::DecodeError)?,
            parent_hash: pad_and_parse_32bytes(&msg.parent_hash)
                .map_err(ExtractionError::DecodeError)?,
            ts: NaiveDateTime::from_timestamp_opt(msg.ts as i64, 0).ok_or_else(|| {
                ExtractionError::DecodeError(format!(
                    "Failed to convert timestamp {} to datetime!",
                    msg.ts
                ))
            })?,
        })
    }
}

impl Transaction {
    /// Parses transaction from tychos protobuf transaction message
    pub fn try_from_message(
        msg: substreams::Transaction,
        block_hash: &H256,
    ) -> Result<Self, ExtractionError> {
        let to = if !msg.to.is_empty() {
            Some(pad_and_parse_h160(&msg.to).map_err(ExtractionError::DecodeError)?)
        } else {
            None
        };
        Ok(Self {
            hash: pad_and_parse_32bytes(&msg.hash).map_err(ExtractionError::DecodeError)?,
            block_hash: *block_hash,
            from: pad_and_parse_h160(&msg.from).map_err(ExtractionError::DecodeError)?,
            to,
            index: msg.index,
        })
    }
}

impl AccountUpdateWithTx {
    /// Parses account update from tychos protobuf account update message
    pub fn try_from_message(
        msg: substreams::ContractChange,
        tx: &Transaction,
        chain: Chain,
    ) -> Result<Self, ExtractionError> {
        let change = msg.change().into();
        let update = AccountUpdateWithTx::new(
            pad_and_parse_h160(&msg.address).map_err(ExtractionError::DecodeError)?,
            chain,
            msg.slots
                .into_iter()
                .map(|cs| {
                    Ok((
                        pad_and_parse_32bytes::<U256>(&cs.slot)
                            .map_err(ExtractionError::DecodeError)?,
                        pad_and_parse_32bytes::<U256>(&cs.value)
                            .map_err(ExtractionError::DecodeError)?,
                    ))
                })
                .collect::<Result<HashMap<_, _>, ExtractionError>>()?,
            if !msg.balance.is_empty() {
                Some(pad_and_parse_32bytes(&msg.balance).map_err(ExtractionError::DecodeError)?)
            } else {
                None
            },
            if !msg.code.is_empty() { Some(msg.code) } else { None },
            change,
            *tx,
        );
        Ok(update)
    }
}

impl From<substreams::ChangeType> for ChangeType {
    fn from(value: substreams::ChangeType) -> Self {
        match value {
            substreams::ChangeType::Unspecified => {
                panic!("Unkown enum member encountered: {:?}", value)
            }
            substreams::ChangeType::Update => ChangeType::Update,
            substreams::ChangeType::Creation => ChangeType::Creation,
            substreams::ChangeType::Deletion => ChangeType::Deletion,
        }
    }
}

impl BlockStateChanges {
    /// Parse from tychos protobuf message
    pub fn try_from_message(
        msg: substreams::BlockContractChanges,
        extractor: &str,
        chain: Chain,
    ) -> Result<Self, ExtractionError> {
        if let Some(block) = msg.block {
            let block = Block::try_from_message(block, chain)?;
            let mut tx_updates = Vec::new();

            for change in msg.changes.into_iter() {
                if let Some(tx) = change.tx {
                    let tx = Transaction::try_from_message(tx, &block.hash)?;
                    for el in change.contract_changes.into_iter() {
                        let update = AccountUpdateWithTx::try_from_message(el, &tx, chain)?;
                        tx_updates.push(update);
                    }
                }
            }
            tx_updates.sort_unstable_by_key(|update| update.tx.index);
            return Ok(Self {
                extractor: extractor.to_owned(),
                chain,
                block,
                tx_updates,
                new_pools: HashMap::new(),
            })
        }
        Err(ExtractionError::Empty)
    }

    /// Aggregates transaction updates.
    ///
    /// This function aggregates the transaction updates (`tx_updates`) from
    /// different accounts into a single object of  
    /// `BlockAccountChanges`. It maintains a HashMap to hold
    /// `AccountUpdate` corresponding to each unique address.
    ///
    /// If the address from an update is already present in the HashMap, it
    /// merges the update with the existing one. Otherwise, it inserts the new
    /// update into the HashMap.
    ///
    /// After merging all updates, a `BlockAccountChanges` object is returned
    /// which contains, amongst other data, the compacted account updates.
    ///
    /// # Errors
    ///
    /// This returns an error if there was a problem during merge. The error
    /// type is `ExtractionError`.
    pub fn aggregate_updates(self) -> Result<BlockAccountChanges, ExtractionError> {
        let mut account_updates: HashMap<H160, AccountUpdateWithTx> = HashMap::new();

        for update in self.tx_updates.into_iter() {
            match account_updates.entry(update.address) {
                Entry::Occupied(mut e) => {
                    e.get_mut().merge(update)?;
                }
                Entry::Vacant(e) => {
                    e.insert(update);
                }
            }
        }

        Ok(BlockAccountChanges::new(
            &self.extractor,
            self.chain,
            self.block,
            account_updates
                .into_iter()
                .map(|(k, v)| (k, v.update))
                .collect(),
        ))
    }
}

#[cfg(test)]
pub mod fixtures {
    use super::*;

    pub const HASH_256_0: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000000";

    pub fn transaction01() -> Transaction {
        Transaction::new(H256::zero(), H256::zero(), H160::zero(), Some(H160::zero()), 10)
    }

    pub fn transaction02(hash: &str, block: &str, index: u64) -> Transaction {
        Transaction::new(
            hash.parse().unwrap(),
            block.parse().unwrap(),
            H160::zero(),
            Some(H160::zero()),
            index,
        )
    }

    pub fn evm_slots(data: impl IntoIterator<Item = (u64, u64)>) -> HashMap<U256, U256> {
        data.into_iter()
            .map(|(s, v)| (U256::from(s), U256::from(v)))
            .collect()
    }

    pub fn pb_block_scoped_data(
        msg: impl prost::Message,
    ) -> crate::pb::sf::substreams::rpc::v2::BlockScopedData {
        use crate::pb::sf::substreams::{rpc::v2::*, v1::Clock};
        let val = msg.encode_to_vec();
        BlockScopedData {
            output: Some(MapModuleOutput {
                name: "map_changes".to_owned(),
                map_output: Some(prost_types::Any {
                    type_url: "tycho.evm.v1.BlockContractChanges".to_owned(),
                    value: val,
                }),
                debug_info: None,
            }),
            clock: Some(Clock {
                id: HASH_256_0.to_owned(),
                number: 420,
                timestamp: Some(prost_types::Timestamp { seconds: 1000, nanos: 0 }),
            }),
            cursor: "cursor@420".to_owned(),
            final_block_height: 405,
            debug_map_outputs: vec![],
            debug_store_outputs: vec![],
        }
    }

    pub fn pb_block_contract_changes() -> crate::pb::tycho::evm::v1::BlockContractChanges {
        use crate::pb::tycho::evm::v1::*;
        BlockContractChanges {
            block: Some(Block {
                hash: vec![0x31, 0x32, 0x33, 0x34],
                parent_hash: vec![0x21, 0x22, 0x23, 0x24],
                number: 1,
                ts: 1000,
            }),

            changes: vec![TransactionChanges {
                tx: Some(Transaction {
                    hash: vec![0x11, 0x12, 0x13, 0x14],
                    from: vec![0x41, 0x42, 0x43, 0x44],
                    to: vec![0x51, 0x52, 0x53, 0x54],
                    index: 2,
                }),
                contract_changes: vec![
                    ContractChange {
                        address: vec![0x61, 0x62, 0x63, 0x64],
                        balance: vec![0x71, 0x72, 0x73, 0x74],
                        code: vec![0x81, 0x82, 0x83, 0x84],
                        slots: vec![
                            ContractSlot {
                                slot: vec![0xa1, 0xa2, 0xa3, 0xa4],
                                value: vec![0xb1, 0xb2, 0xb3, 0xb4],
                            },
                            ContractSlot {
                                slot: vec![0xc1, 0xc2, 0xc3, 0xc4],
                                value: vec![0xd1, 0xd2, 0xd3, 0xd4],
                            },
                        ],
                        change: ChangeType::Update.into(),
                    },
                    ContractChange {
                        address: vec![0x61, 0x62, 0x63, 0x64],
                        balance: vec![0xf1, 0xf2, 0xf3, 0xf4],
                        code: vec![0x01, 0x02, 0x03, 0x04],
                        slots: vec![
                            ContractSlot {
                                slot: vec![0x91, 0x92, 0x93, 0x94],
                                value: vec![0xa1, 0xa2, 0xa3, 0xa4],
                            },
                            ContractSlot {
                                slot: vec![0xb1, 0xb2, 0xb3, 0xb4],
                                value: vec![0xc1, 0xc2, 0xc3, 0xc4],
                            },
                        ],
                        change: ChangeType::Update.into(),
                    },
                ],
                components: todo!(),
                tvl: todo!(),
            }],
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use prost::Message;
    use rstest::rstest;

    const HASH_256_0: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
    const HASH_256_1: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";

    fn account01() -> Account {
        let code = vec![0, 0, 0, 0];
        let code_hash = H256(keccak256(&code));
        Account::new(
            Chain::Ethereum,
            "0xe688b84b23f322a994A53dbF8E15FA82CDB71127"
                .parse()
                .unwrap(),
            "0xe688b84b23f322a994a53dbf8e15fa82cdb71127".into(),
            fixtures::evm_slots([]),
            U256::from(10000),
            code,
            code_hash,
            H256::zero(),
            H256::zero(),
            Some(H256::zero()),
        )
    }

    fn update_w_tx() -> AccountUpdateWithTx {
        let code = vec![0, 0, 0, 0];
        AccountUpdateWithTx::new(
            "0xe688b84b23f322a994A53dbF8E15FA82CDB71127"
                .parse()
                .unwrap(),
            Chain::Ethereum,
            fixtures::evm_slots([]),
            Some(U256::from(10000)),
            Some(code),
            ChangeType::Update,
            fixtures::transaction01(),
        )
    }

    fn update_balance() -> AccountUpdate {
        AccountUpdate::new(
            "0xe688b84b23f322a994A53dbF8E15FA82CDB71127"
                .parse()
                .unwrap(),
            Chain::Ethereum,
            fixtures::evm_slots([]),
            Some(U256::from(420)),
            None,
            ChangeType::Update,
        )
    }

    fn update_slots() -> AccountUpdate {
        AccountUpdate::new(
            "0xe688b84b23f322a994A53dbF8E15FA82CDB71127"
                .parse()
                .unwrap(),
            Chain::Ethereum,
            fixtures::evm_slots([(0, 1), (1, 2)]),
            None,
            None,
            ChangeType::Update,
        )
    }

    #[rstest]
    fn test_account_from_update_w_tx() {
        let update = update_w_tx();
        let exp = account01();

        assert_eq!(Account::from(&update), exp);
    }

    #[rstest]
    fn test_merge_account_update() {
        let mut update_left = update_balance();
        let update_right = update_slots();
        let mut exp = update_slots();
        exp.balance = Some(U256::from(420));

        update_left.merge(update_right).unwrap();

        assert_eq!(update_left, exp);
    }

    #[rstest]
    fn test_merge_account_update_wrong_address() {
        let mut update_left = update_balance();
        let mut update_right = update_slots();
        update_right.address = H160::zero();
        let exp = Err(ExtractionError::Unknown(
            "Can't merge AccountUpdates from differing identities; \
            Expected 0xe688b84b23f322a994a53dbf8e15fa82cdb71127, \
            got 0x0000000000000000000000000000000000000000"
                .into(),
        ));

        let res = update_left.merge(update_right);

        assert_eq!(res, exp);
    }

    #[rstest]
    #[case::diff_block(
        fixtures::transaction02(HASH_256_1, HASH_256_1, 11),
        Err(ExtractionError::Unknown(format!("Can't merge AccountUpdates from different blocks: 0x{:x} != {}", H256::zero(), HASH_256_1)))
    )]
    #[case::same_tx(
        fixtures::transaction02(HASH_256_0, HASH_256_0, 11),
        Err(ExtractionError::Unknown(format!("Can't merge AccountUpdates from the same transaction: 0x{:x}", H256::zero())))
    )]
    #[case::lower_idx(
        fixtures::transaction02(HASH_256_1, HASH_256_0, 1),
        Err(ExtractionError::Unknown("Can't merge AccountUpdates with lower transaction index: 10 > 1".to_owned()))
    )]
    fn test_merge_account_update_w_tx(
        #[case] tx: Transaction,
        #[case] exp: Result<(), ExtractionError>,
    ) {
        let mut left = update_w_tx();
        let mut right = left.clone();
        right.tx = tx;

        let res = left.merge(right);

        assert_eq!(res, exp);
    }

    fn block_state_changes() -> BlockStateChanges {
        let tx = Transaction {
            hash: H256::from_low_u64_be(
                0x0000000000000000000000000000000000000000000000000000000011121314,
            ),
            block_hash: H256::from_low_u64_be(
                0x0000000000000000000000000000000000000000000000000000000031323334,
            ),
            from: H160::from_low_u64_be(0x0000000000000000000000000000000041424344),
            to: Some(H160::from_low_u64_be(0x0000000000000000000000000000000051525354)),
            index: 2,
        };
        BlockStateChanges {
            extractor: "test".to_string(),
            chain: Chain::Ethereum,
            block: Block {
                number: 1,
                hash: H256::from_low_u64_be(
                    0x0000000000000000000000000000000000000000000000000000000031323334,
                ),
                parent_hash: H256::from_low_u64_be(
                    0x0000000000000000000000000000000000000000000000000000000021222324,
                ),
                chain: Chain::Ethereum,
                ts: NaiveDateTime::from_timestamp_opt(1000, 0).unwrap(),
            },
            tx_updates: vec![
                AccountUpdateWithTx {
                    update: AccountUpdate {
                        address: H160::from_low_u64_be(0x0000000000000000000000000000000061626364),
                        chain: Chain::Ethereum,
                        slots: fixtures::evm_slots([
                            (2711790500, 2981278644),
                            (3250766788, 3520254932),
                        ]),
                        balance: Some(U256::from(1903326068)),
                        code: Some(vec![129, 130, 131, 132]),
                        change: ChangeType::Update,
                    },
                    tx,
                },
                AccountUpdateWithTx {
                    update: AccountUpdate {
                        address: H160::from_low_u64_be(0x0000000000000000000000000000000061626364),
                        chain: Chain::Ethereum,
                        slots: fixtures::evm_slots([
                            (2981278644, 3250766788),
                            (2442302356, 2711790500),
                        ]),
                        balance: Some(U256::from(4059231220u64)),
                        code: Some(vec![1, 2, 3, 4]),
                        change: ChangeType::Update,
                    },
                    tx,
                },
            ],
            new_pools: HashMap::new(),
        }
    }

    #[rstest]
    fn test_block_state_changes_parse_msg() {
        let msg = fixtures::pb_block_contract_changes();

        let res = BlockStateChanges::try_from_message(msg, "test", Chain::Ethereum).unwrap();

        assert_eq!(res, block_state_changes());
    }

    fn block_account_changes() -> BlockAccountChanges {
        let address = H160::from_low_u64_be(0x0000000000000000000000000000000061626364);
        BlockAccountChanges::new(
            "test",
            Chain::Ethereum,
            Block {
                number: 1,
                hash: H256::from_low_u64_be(
                    0x0000000000000000000000000000000000000000000000000000000031323334,
                ),
                parent_hash: H256::from_low_u64_be(
                    0x0000000000000000000000000000000000000000000000000000000021222324,
                ),
                chain: Chain::Ethereum,
                ts: NaiveDateTime::from_timestamp_opt(1000, 0).unwrap(),
            },
            vec![(
                address,
                AccountUpdate {
                    address: H160::from_low_u64_be(0x0000000000000000000000000000000061626364),
                    chain: Chain::Ethereum,
                    slots: fixtures::evm_slots([
                        (2711790500, 2981278644),
                        (3250766788, 3520254932),
                        (2981278644, 3250766788),
                        (2442302356, 2711790500),
                    ]),
                    balance: Some(U256::from(4059231220u64)),
                    code: Some(vec![1, 2, 3, 4]),
                    change: ChangeType::Update,
                },
            )]
            .into_iter()
            .collect(),
        )
    }

    #[rstest]
    fn test_block_state_changes_aggregate() {
        let mut msg = block_state_changes();
        let block_hash = "0x0000000000000000000000000000000000000000000000000000000031323334";
        // use a different tx so merge works
        msg.tx_updates[1].tx = fixtures::transaction02(HASH_256_1, block_hash, 5);

        // should error cause same tx
        let res = msg.aggregate_updates().unwrap();

        assert_eq!(res, block_account_changes());
    }

    #[rstest]
    fn test_try_from_message_tvl_change() {
        let tx = Transaction {
            hash: H256::from_low_u64_be(
                0x0000000000000000000000000000000000000000000000000000000011121314,
            ),
            block_hash: H256::from_low_u64_be(
                0x0000000000000000000000000000000000000000000000000000000031323334,
            ),
            from: H160::from_low_u64_be(0x0000000000000000000000000000000041424344),
            to: Some(H160::from_low_u64_be(0x0000000000000000000000000000000051525354)),
            index: 2,
        };
        let expected_balance = U256::from("3000");
        let msg_balance = expected_balance
            .to_big_endian(&mut [0; 32])
            .encode_to_vec();

        let expected_token = H160::from_low_u64_be(55);
        let msg_token = expected_token.to_fixed_bytes().to_vec();

        let msg = substreams::TvlUpdate { balance: msg_balance, token: msg_token };
        let from_message = TvlChange::try_from_message(msg, &tx).unwrap();

        assert_eq!(from_message.new_balance, expected_balance);
        assert_eq!(from_message.tx, tx.hash);
        assert_eq!(from_message.token, expected_token);
    }
}
