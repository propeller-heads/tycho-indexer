pub struct PoolConfig {
    pub fee: Vec<u8>,
    pub tick_spacing: Vec<u8>,
    pub extension: Vec<u8>,
}

impl From<[u8; 32]> for PoolConfig {
    fn from(value: [u8; 32]) -> Self {
        Self {
            tick_spacing: value[28..32].into(),
            fee: value[20..28].into(),
            extension: value[..20].into(),
        }
    }
}
