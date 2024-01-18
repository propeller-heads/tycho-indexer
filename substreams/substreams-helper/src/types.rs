pub enum Network {
    Ethereum,
}

pub enum Source {
    Oracles = 0,
    ChainlinkAggregators = 1,
    UniswapFeeds = 2,
}

pub type Address = [u8; 20];
