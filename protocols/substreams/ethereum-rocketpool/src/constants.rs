use crate::utils::StorageLocation;
use substreams::hex;

pub const ETH_ADDRESS: [u8; 20] = hex!("0000000000000000000000000000000000000000");
pub const RETH_ADDRESS: [u8; 20] = hex!("ae78736Cd615f374D3085123A210448E74Fc6393");

pub const ROCKET_POOL_COMPONENT_ID: &str = "0xdd3f50f8a6cafbe9b31a427582963f465e745af8";

pub const ROCKET_NETWORK_BALANCES_ADDRESS: [u8; 20] =
    hex!("6Cc65bF618F55ce2433f9D8d827Fc44117D81399");
pub const ROCKET_DEPOSIT_POOL_ADDRESS: [u8; 20] = hex!("DD3f50F8A6CafbE9b31a427582963f465E745AF8");
pub const ROCKET_DAO_PROTOCOL_SETTINGS_DEPOSIT_ADDRESS: [u8; 20] =
    hex!("D846AA34caEf083DC4797d75096F60b6E08B7418");
pub const ROCKET_DAO_PROTOCOL_PROPOSAL_ADDRESS: [u8; 20] =
    hex!("2D627A50Dc1C4EDa73E42858E8460b0eCF300b25");

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

pub const TRACKED_STORAGE_LOCATIONS: [StorageLocation; 4] =
    [DEPOSITS_ENABLED_SLOT, MIN_DEPOSIT_AMOUNT_SLOT, MAX_DEPOSIT_AMOUNT_SLOT, DEPOSIT_FEE_SLOT];
