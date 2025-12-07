use alloy_primitives::Address;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct DeploymentConfig {
    pub core: Address,
    pub oracle: Address,
    pub twamm: Address,
    pub mev_capture: Address,
}
