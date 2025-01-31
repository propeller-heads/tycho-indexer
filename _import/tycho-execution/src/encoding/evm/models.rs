use tycho_core::models::Chain;

pub struct ChainId(u64);

impl ChainId {
    pub fn id(&self) -> u64 {
        self.0
    }
}

impl From<Chain> for ChainId {
    fn from(chain: Chain) -> Self {
        match chain {
            Chain::Ethereum => ChainId(1),
            Chain::ZkSync => ChainId(324),
            Chain::Arbitrum => ChainId(42161),
            Chain::Starknet => ChainId(0),
        }
    }
}
