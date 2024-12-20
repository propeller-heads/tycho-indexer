use alloy_primitives::{Address, U256};
use lazy_static::lazy_static;

use crate::protocol::errors::SimulationError;

lazy_static! {
    pub static ref EXTERNAL_ACCOUNT: Address = Address::from_slice(
        &hex::decode("f847a638E44186F3287ee9F8cAF73FF4d4B80784")
            .expect("Invalid string for external account address"),
    );
    pub static ref MAX_BALANCE: U256 = U256::MAX / U256::from(2);
}

pub const ERC20_BYTECODE: &[u8] = include_bytes!("assets/ERC20.bin");
pub const BALANCER_V2: &[u8] = include_bytes!("assets/BalancerV2SwapAdapter.evm.runtime");
pub const CURVE: &[u8] = include_bytes!("assets/CurveSwapAdapter.evm.runtime");
pub fn get_adapter_file(protocol: &str) -> Result<&'static [u8], SimulationError> {
    match protocol {
        "balancer_v2" => Ok(BALANCER_V2),
        "curve" => Ok(CURVE),
        _ => {
            Err(SimulationError::FatalError(format!("Adapter for protocol {} not found", protocol)))
        }
    }
}
