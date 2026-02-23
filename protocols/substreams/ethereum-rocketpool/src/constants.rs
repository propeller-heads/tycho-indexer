use crate::utils::StorageLocation;
use substreams::hex;

pub const ROCKET_POOL_COMPONENT_ID: &str = "0xdd3f50f8a6cafbe9b31a427582963f465e745af8";

pub const ETH_ADDRESS: [u8; 20] = hex!("0000000000000000000000000000000000000000");
pub const RETH_ADDRESS: [u8; 20] = hex!("ae78736Cd615f374D3085123A210448E74Fc6393");

pub const ROCKET_VAULT_ADDRESS: [u8; 20] = hex!("3bDC69C4E5e13E52A65f5583c23EFB9636b469d6");
pub const ROCKET_STORAGE_ADDRESS: [u8; 20] = hex!("1d8f8f00cfa6758d7bE78336684788Fb0ee0Fa46");

pub const ROCKET_DAO_MINIPOOL_QUEUE_ADDRESS: [u8; 20] =
    hex!("9e966733e3E9BFA56aF95f762921859417cF6FaA");
/// Rocket Network Balances was upgraded to v2 at the same block as Rocket Pool Deposit v1.2 upgrade
pub const ROCKET_NETWORK_BALANCES_ADDRESS_V2: [u8; 20] =
    hex!("07FCaBCbe4ff0d80c2b1eb42855C0131b6cba2F4");
/// Rocket Network Balances was upgraded to v3 at the same block 20107789
pub const ROCKET_NETWORK_BALANCES_ADDRESS_V3: [u8; 20] =
    hex!("6Cc65bF618F55ce2433f9D8d827Fc44117D81399");
/// Rocket Network Balances was upgraded to v4 at Saturn activation block 24479942
pub const ROCKET_NETWORK_BALANCES_ADDRESS_V4: [u8; 20] =
    hex!("1D9F14C6Bfd8358b589964baD8665AdD248E9473");
pub const ROCKET_DAO_PROTOCOL_PROPOSAL_ADDRESS: [u8; 20] =
    hex!("2D627A50Dc1C4EDa73E42858E8460b0eCF300b25");
pub const ROCKET_DEPOSIT_POOL_ADDRESS_V1_2: [u8; 20] =
    hex!("DD3f50F8A6CafbE9b31a427582963f465E745AF8");
/// Rocket Deposit Pool v4 deployed with Saturn I upgrade, activated at block 24479942
pub const ROCKET_DEPOSIT_POOL_ADDRESS_V4: [u8; 20] =
    hex!("CE15294273CFb9D9b628F4D61636623decDF4fdC");

/// Saturn I activation block — the block where v4 contracts were registered in RocketStorage.
/// All v4 contract events start from this block.
pub const SATURN_ACTIVATION_BLOCK: u64 = 24479942;

/// All storage slots for initial state and settings tracking.
/// These are EVM storage slots in RocketStorage (base slot 2 for uintStorage, 5 for boolStorage).
/// The settings key format is: keccak256(keccak256("dao.protocol.setting.deposit") ++ settingPath)
/// and the EVM slot is: keccak256(abi.encode(key, mapping_base_slot)).
/// These slots are UNCHANGED between v3 and v4 because the eternal storage key strings are the same.
pub(crate) const ALL_STORAGE_SLOTS: [StorageLocation; 10] = [
    ROCKET_DEPOSIT_POOL_ETH_BALANCE_SLOT,
    DEPOSITS_ENABLED_SLOT,
    DEPOSIT_ASSIGN_ENABLED_SLOT,
    DEPOSIT_ASSIGN_MAXIMUM_SLOT,
    DEPOSIT_ASSIGN_SOCIALISED_MAXIMUM_SLOT,
    MIN_DEPOSIT_AMOUNT_SLOT,
    MAX_DEPOSIT_POOL_SIZE_SLOT,
    DEPOSIT_FEE_SLOT,
    QUEUE_VARIABLE_START_SLOT,
    QUEUE_VARIABLE_END_SLOT,
];

/// Storage slots added in Saturn v4 for megapool queue tracking.
pub(crate) const SATURN_STORAGE_SLOTS: [StorageLocation; 3] = [
    MEGAPOOL_QUEUE_REQUESTED_TOTAL_SLOT,
    MEGAPOOL_QUEUE_INDEX_SLOT,
    EXPRESS_QUEUE_RATE_SLOT,
];

// ----------- Contract: Rocket Vault -----------
pub(crate) const ROCKET_DEPOSIT_POOL_ETH_BALANCE_SLOT: StorageLocation = StorageLocation {
    name: "deposit_contract_balance",
    slot: hex!("00ab4654686e0d7a1f921cc85a932fd8efbc8a1f247b51fa6bca2f7a3976a5bb"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

// ----------- Contract: Rocket Storage (pre-Saturn queue) -----------
pub(crate) const QUEUE_VARIABLE_START_SLOT: StorageLocation = StorageLocation {
    name: "queue_variable_start",
    slot: hex!("3d568e1d0910a705e47c1e34016aabfe207c556ec3d7b6bced9112251062388b"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

pub(crate) const QUEUE_VARIABLE_END_SLOT: StorageLocation = StorageLocation {
    name: "queue_variable_end",
    slot: hex!("f4cc19457af09f7bd6b792f1932b490f46f646363b59314a4c6ad6ef1c9f44e4"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

// ----------- Contract: Rocket Storage (settings — unchanged between v3 and v4) -----------
pub(crate) const DEPOSITS_ENABLED_SLOT: StorageLocation = StorageLocation {
    name: "deposits_enabled",
    slot: hex!("7bd5d699fdfcd0cf7b26d3fc339f1567cecb978e8ce24b7b6ed7d192e1bbb663"),
    offset: 0,
    number_of_bytes: 1,
    signed: false,
};

pub(crate) const MIN_DEPOSIT_AMOUNT_SLOT: StorageLocation = StorageLocation {
    name: "min_deposit_amount",
    slot: hex!("ba4dab8f9b8f22679cf8c926f5bd528d08a526cbe2bb39d1b1f1566d0d30ad0c"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

pub(crate) const MAX_DEPOSIT_POOL_SIZE_SLOT: StorageLocation = StorageLocation {
    name: "max_deposit_pool_size",
    slot: hex!("efeb8d9f341f931c14ed8c1156bdb235390b183f1b94f522d4d72c5d24779598"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

pub(crate) const DEPOSIT_FEE_SLOT: StorageLocation = StorageLocation {
    name: "deposit_fee",
    slot: hex!("a1713e68e8e6d7580de48bb14bd78c7f293a5a0e42a40f7fe428d9943dc63264"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

pub(crate) const DEPOSIT_ASSIGN_ENABLED_SLOT: StorageLocation = StorageLocation {
    name: "deposit_assigning_enabled",
    slot: hex!("3c4ef260cb76105ef0fda3d75cf7af776accf2a871c39fd5530453efa532aba4"),
    offset: 0,
    number_of_bytes: 1,
    signed: false,
};

pub(crate) const DEPOSIT_ASSIGN_MAXIMUM_SLOT: StorageLocation = StorageLocation {
    name: "deposit_assign_maximum",
    slot: hex!("a2574dbdd30c823af5a27800f3329b5f8f5fa1e4cb116c254794974425497fb3"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

pub(crate) const DEPOSIT_ASSIGN_SOCIALISED_MAXIMUM_SLOT: StorageLocation = StorageLocation {
    name: "deposit_assign_socialised_maximum",
    slot: hex!("d6794381ca0356c0f5fabe729b1ea706b25013e48d1d1bb2441c2bd5053a975a"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

// ----------- Contract: Rocket Storage (Saturn v4 megapool queue) -----------
/// Total ETH requested across both express and standard megapool queues.
/// Storage key: keccak256("deposit.pool.requested.total") in uintStorage (base slot 2).
pub(crate) const MEGAPOOL_QUEUE_REQUESTED_TOTAL_SLOT: StorageLocation = StorageLocation {
    name: "megapool_queue_requested_total",
    slot: hex!("70acbb59da22199e2dc0759d60b0224ec935b6c5c70975c698025712f413ccdd"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

/// Round-robin index for express/standard queue assignment.
/// Storage key: keccak256("megapool.queue.index") in uintStorage (base slot 2).
pub(crate) const MEGAPOOL_QUEUE_INDEX_SLOT: StorageLocation = StorageLocation {
    name: "megapool_queue_index",
    slot: hex!("f64759318134d5196993dc645609e8125eff4429ad94d537e335f2d6388069d7"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

/// Express queue rate: how many express assignments per standard assignment.
/// Storage key: keccak256(keccak256("dao.protocol.setting.deposit") ++ "express.queue.rate")
/// in uintStorage (base slot 2).
pub(crate) const EXPRESS_QUEUE_RATE_SLOT: StorageLocation = StorageLocation {
    name: "express_queue_rate",
    slot: hex!("76db7078bc37e9c3634c81dc384e741875c5d95ee6d5bcae0fb5d844d3189423"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

// ----------- Queue Keys (keccak256 hashes) — pre-Saturn only -----------
// These are used to identify which queue type an event belongs to
pub(crate) const QUEUE_KEY_FULL: [u8; 32] =
    hex!("885adb3a1c7cf88a1f3627e1265f3090cd728e0fc96765288e91e8777267ff78");
pub(crate) const QUEUE_KEY_HALF: [u8; 32] =
    hex!("6eea9e53dc9c4fb5c4b0ba0e9db7370a823b1513965347e82945eb8966218188");
pub(crate) const QUEUE_KEY_VARIABLE: [u8; 32] =
    hex!("a7c30d79bac38383b63cf527b2a68c8a7efff3ba22dfd5b81d98030643ef0fca");
