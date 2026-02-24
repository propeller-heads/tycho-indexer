use crate::utils::StorageLocation;
use substreams::hex;

pub const ROCKET_POOL_COMPONENT_ID: &str = "0xdd3f50f8a6cafbe9b31a427582963f465e745af8";

/// The Saturn I upgrade `execute()` transaction — activates all v4 contracts and settings.
/// Contract: RocketUpgradeOneDotFour (0x5b3B5C76391662e56d0ff72F31B89C409316c8Ba)
pub const SATURN_I_UPGRADE_TX: [u8; 32] =
    hex!("2fc10aad3c1b00bdfa9b6fddab79e0f2688609848f8f7a1a6449ab42da38530c");

pub const ETH_ADDRESS: [u8; 20] = hex!("0000000000000000000000000000000000000000");
pub const RETH_ADDRESS: [u8; 20] = hex!("ae78736Cd615f374D3085123A210448E74Fc6393");

pub const ROCKET_VAULT_ADDRESS: [u8; 20] = hex!("3bDC69C4E5e13E52A65f5583c23EFB9636b469d6");
pub const ROCKET_STORAGE_ADDRESS: [u8; 20] = hex!("1d8f8f00cfa6758d7bE78336684788Fb0ee0Fa46");

/// Rocket Network Balances v4 — deployed with Saturn I upgrade
pub const ROCKET_NETWORK_BALANCES_ADDRESS_V4: [u8; 20] =
    hex!("1D9F14C6Bfd8358b589964baD8665AdD248E9473");
pub const ROCKET_DAO_PROTOCOL_PROPOSAL_ADDRESS: [u8; 20] =
    hex!("2D627A50Dc1C4EDa73E42858E8460b0eCF300b25");
/// Rocket Deposit Pool v4 — deployed with Saturn I upgrade, activated at block 24479942
pub const ROCKET_DEPOSIT_POOL_ADDRESS_V4: [u8; 20] =
    hex!("CE15294273CFb9D9b628F4D61636623decDF4fdC");

/// All storage slots for initial state and settings tracking.
/// These are EVM storage slots in RocketStorage (base slot 2 for uintStorage, 5 for boolStorage).
/// The settings key format is: keccak256(keccak256("dao.protocol.setting.deposit") ++ settingPath)
/// and the EVM slot is: keccak256(abi.encode(key, mapping_base_slot)).
pub(crate) const ALL_STORAGE_SLOTS: [StorageLocation; 11] = [
    ROCKET_DEPOSIT_POOL_ETH_BALANCE_SLOT,
    DEPOSITS_ENABLED_SLOT,
    DEPOSIT_ASSIGN_ENABLED_SLOT,
    DEPOSIT_ASSIGN_MAXIMUM_SLOT,
    DEPOSIT_ASSIGN_SOCIALISED_MAXIMUM_SLOT,
    MIN_DEPOSIT_AMOUNT_SLOT,
    MAX_DEPOSIT_POOL_SIZE_SLOT,
    DEPOSIT_FEE_SLOT,
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

// ----------- Contract: Rocket Storage (settings) -----------
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
