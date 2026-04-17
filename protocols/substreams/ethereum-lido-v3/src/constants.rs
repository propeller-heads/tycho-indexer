use substreams::hex;

pub const STETH_COMPONENT_ID: &str = "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84";
pub const WSTETH_COMPONENT_ID: &str = "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0";

pub const STETH_ADDRESS: [u8; 20] = hex!("ae7ab96520de3a18e5e111b5eaab095312d7fe84");
pub const WSTETH_ADDRESS: [u8; 20] = hex!("7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0");
pub const ETH_ADDRESS: [u8; 20] = hex!("0000000000000000000000000000000000000000");

pub const TOTAL_AND_EXTERNAL_SHARES_POSITION: [u8; 32] =
    hex!("6038150aecaa250d524370a0fdcdec13f2690e0723eaf277f41d7cae26b359e6");
pub const BUFFERED_ETHER_AND_DEPOSITED_VALIDATORS_POSITION: [u8; 32] =
    hex!("a84c096ee27e195f25d7b6c7c2a03229e49f1a2a5087e57ce7d7127707942fe3");
pub const CL_BALANCE_AND_CL_VALIDATORS_POSITION: [u8; 32] =
    hex!("c36804a03ec742b57b141e4e5d8d3bd1ddb08451fd0f9983af8aaab357a78e2f");
pub const STAKING_STATE_POSITION: [u8; 32] =
    hex!("a3678de4a579be090bed1177e0a24f77cc29d181ac22fd7688aca344d8938015");

pub const TOTAL_SHARES_ATTR: &str = "total_shares";
pub const EXTERNAL_SHARES_ATTR: &str = "external_shares";
pub const BUFFERED_ETHER_ATTR: &str = "buffered_ether";
pub const DEPOSITED_VALIDATORS_ATTR: &str = "deposited_validators";
pub const CL_BALANCE_ATTR: &str = "cl_balance";
pub const CL_VALIDATORS_ATTR: &str = "cl_validators";
pub const STAKING_STATE_ATTR: &str = "staking_state";
pub const INTERNAL_ETHER_ATTR: &str = "internal_ether";
pub const INTERNAL_SHARES_ATTR: &str = "internal_shares";
