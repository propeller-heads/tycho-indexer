pub use map_component_balance::map_component_balance;
pub use map_protocol_components::map_protocol_components;
pub use store_protocol_components::store_protocol_components;
use substreams::hex;

#[path = "1_map_components.rs"]
mod map_protocol_components;

#[path = "2_store_components.rs"]
mod store_protocol_components;

#[path = "3_map_component_balance.rs"]
mod map_component_balance;

pub const ST_ETH_ADDRESS_OUTER: [u8; 20] = hex!("ae7ab96520DE3A18E5e111B5EaAb095312D7fE84");
pub const ST_ETH_ADDRESS_OUTER_COMPONENT_ID: &str = "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84";
pub const ST_ETH_ADDRESS: [u8; 20] = hex!("17144556fd3424EDC8Fc8A4C940B2D04936d17eb");
pub const ST_ETH_ADDRESS_COMPONENT_ID: &str = "0x17144556fd3424edc8fc8a4c940b2d04936d17eb";
pub const WST_ETH_ADDRESS: [u8; 20] = hex!("7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0");
pub const WST_ETH_ADDRESS_COMPONENT_ID: &str = "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0";
pub const ETH_ADDRESS: [u8; 20] = hex!("0000000000000000000000000000000000000000");
