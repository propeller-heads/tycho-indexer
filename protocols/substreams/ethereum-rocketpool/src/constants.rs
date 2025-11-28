use crate::utils::StorageLocation;
use substreams::hex;

pub const ETH_ADDRESS: [u8; 20] = hex!("0000000000000000000000000000000000000000");
pub const RETH_ADDRESS: [u8; 20] = hex!("ae78736Cd615f374D3085123A210448E74Fc6393");

pub const ROCKET_POOL_COMPONENT_ID: &str = "0xdd3f50f8a6cafbe9b31a427582963f465e745af8";

pub const ROCKET_VAULT_ADDRESS: [u8; 20] = hex!("3bDC69C4E5e13E52A65f5583c23EFB9636b469d6");
pub const ROCKET_STORAGE_ADDRESS: [u8; 20] = hex!("1d8f8f00cfa6758d7bE78336684788Fb0ee0Fa46");
pub const ROCKET_DAO_MINIPOOL_QUEUE_ADDRESS: [u8; 20] =
    hex!("9e966733e3E9BFA56aF95f762921859417cF6FaA");
pub const ROCKET_NETWORK_BALANCES_ADDRESS: [u8; 20] =
    hex!("6Cc65bF618F55ce2433f9D8d827Fc44117D81399");
pub const ROCKET_DAO_PROTOCOL_PROPOSAL_ADDRESS: [u8; 20] =
    hex!("2D627A50Dc1C4EDa73E42858E8460b0eCF300b25");

pub const ROCKET_DEPOSIT_POOL_ADDRESS_V1_0: [u8; 20] =
    hex!("4D05E3d48a938db4b7a9A59A802D5b45011BDe58");
pub const ROCKET_DEPOSIT_POOL_ADDRESS_V1_1: [u8; 20] =
    hex!("2cac916b2A963Bf162f076C0a8a4a8200BCFBfb4");
pub const ROCKET_DEPOSIT_POOL_ADDRESS_V1_2: [u8; 20] =
    hex!("DD3f50F8A6CafbE9b31a427582963f465E745AF8");

pub const ROCKET_DEPOSIT_POOL_ADDRESSES: [&[u8]; 3] = [
    &ROCKET_DEPOSIT_POOL_ADDRESS_V1_0,
    &ROCKET_DEPOSIT_POOL_ADDRESS_V1_1,
    &ROCKET_DEPOSIT_POOL_ADDRESS_V1_2,
];

// ----------- Contract: Rocket Vault -----------
pub const ROCKET_DEPOSIT_POOL_ETH_BALANCE_SLOT: StorageLocation = StorageLocation {
    name: "liquidity",
    slot: hex!("00ab4654686e0d7a1f921cc85a932fd8efbc8a1f247b51fa6bca2f7a3976a5bb"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

// ----------- Contract: Rocket Storage -----------
const QUEUE_FULL_START_SLOT: StorageLocation = StorageLocation {
    name: "queue_full_start",
    slot: hex!("66fbb2bc01c7f3354379985511bb047cddc3089cc9aa6432e0b4de8646473756"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

const QUEUE_FULL_END_SLOT: StorageLocation = StorageLocation {
    name: "queue_full_end",
    slot: hex!("a9ca39f6099c1d39d48a086017baafe1c63c2875fbe17fab99a52408cbbc80ad"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

const QUEUE_HALF_START_SLOT: StorageLocation = StorageLocation {
    name: "queue_half_start",
    slot: hex!("ada5623cd46c40afb4bc5a397a7e76242f78a98958558c5d20ca1574e2fcd02e"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

const QUEUE_HALF_END_SLOT: StorageLocation = StorageLocation {
    name: "queue_half_end",
    slot: hex!("49585eaefe7634c78147facb0153201345aa8526bd04dfba2c88d373611930c6"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

const QUEUE_VARIABLE_START_SLOT: StorageLocation = StorageLocation {
    name: "queue_variable_start",
    slot: hex!("3d568e1d0910a705e47c1e34016aabfe207c556ec3d7b6bced9112251062388b"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

pub const QUEUE_VARIABLE_END_SLOT: StorageLocation = StorageLocation {
    name: "queue_variable_end",
    slot: hex!("f4cc19457af09f7bd6b792f1932b490f46f646363b59314a4c6ad6ef1c9f44e4"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

const DEPOSITS_ENABLED_SLOT: StorageLocation = StorageLocation {
    name: "deposits_enabled",
    slot: hex!("7bd5d699fdfcd0cf7b26d3fc339f1567cecb978e8ce24b7b6ed7d192e1bbb663"),
    offset: 0,
    number_of_bytes: 1,
    signed: false,
};

const MIN_DEPOSIT_AMOUNT_SLOT: StorageLocation = StorageLocation {
    name: "min_deposit_amount",
    slot: hex!("ba4dab8f9b8f22679cf8c926f5bd528d08a526cbe2bb39d1b1f1566d0d30ad0c"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

const MAX_DEPOSIT_AMOUNT_SLOT: StorageLocation = StorageLocation {
    name: "max_deposit_amount",
    slot: hex!("efeb8d9f341f931c14ed8c1156bdb235390b183f1b94f522d4d72c5d24779598"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

const DEPOSIT_FEE_SLOT: StorageLocation = StorageLocation {
    name: "deposit_fee",
    slot: hex!("a1713e68e8e6d7580de48bb14bd78c7f293a5a0e42a40f7fe428d9943dc63264"),
    offset: 0,
    number_of_bytes: 32,
    signed: false,
};

pub const DEPOSIT_SETTINGS_SLOTS: [StorageLocation; 4] =
    [DEPOSITS_ENABLED_SLOT, MIN_DEPOSIT_AMOUNT_SLOT, MAX_DEPOSIT_AMOUNT_SLOT, DEPOSIT_FEE_SLOT];

// Queue storage location arrays for RocketStorage contract
pub const QUEUE_START_SLOTS: [StorageLocation; 3] =
    [QUEUE_FULL_START_SLOT, QUEUE_HALF_START_SLOT, QUEUE_VARIABLE_START_SLOT];

pub const QUEUE_END_SLOTS: [StorageLocation; 3] =
    [QUEUE_FULL_END_SLOT, QUEUE_HALF_END_SLOT, QUEUE_VARIABLE_END_SLOT];
