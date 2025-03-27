use serde::Deserialize;

#[derive(Deserialize)]
pub struct DeploymentConfig {
    #[serde(with = "hex::serde")]
    pub core: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub oracle: Vec<u8>,
}
