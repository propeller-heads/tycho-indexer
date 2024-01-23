// TODO: Check which ones are still relevant and remove the rest
#[derive(Clone)]
pub enum StoreKey {
    Pool,
    TotalBalance,
    LatestTimestamp,
    LatestBlockNumber,
    TokenBalance,
    Token0Balance,
    Token1Balance,
    OutputTokenBalance,
    TokenPrice,
    TotalValueLockedUSD,
    Volume,
}

impl StoreKey {
    pub fn get_unique_pool_key(&self, key: &str) -> String {
        format!("{}:{}", self.unique_id(), key)
    }

    pub fn get_unique_pair_key(&self, key1: &str, key2: &str) -> String {
        format!("{}:{}:{}", self.unique_id(), key1, key2)
    }

    pub fn get_unique_protocol_key(&self) -> String {
        format!("[Protocol]:{}", self.unique_id())
    }

    pub fn get_unique_snapshot_key(&self, id: i64, keys: Vec<&str>) -> String {
        format!("{}:{}:{}", self.unique_id(), id, keys.join(":"))
    }

    pub fn get_unique_daily_protocol_key(&self, day_id: i64) -> String {
        format!("[Protocol]:{}:{}", self.unique_id(), day_id)
    }

    pub fn get_unique_snapshot_tracking_key(&self, key1: &str, key2: &str) -> String {
        format!("{}:{}:{}", self.unique_id(), key1, key2)
    }

    pub fn get_pool(&self, key: &str) -> Option<String> {
        let chunks: Vec<&str> = key.split(":").collect();

        if chunks[0] != self.unique_id() {
            return None;
        }
        return Some(chunks[1].to_string());
    }

    pub fn get_pool_and_token(&self, key: &str) -> Option<(String, String)> {
        let chunks: Vec<&str> = key.split(":").collect();

        if chunks[0] != self.unique_id() {
            return None;
        }
        return Some((chunks[1].to_string(), chunks[2].to_string()));
    }

    pub fn unique_id(&self) -> String {
        match self {
            StoreKey::Pool => "Pool".to_string(),
            StoreKey::TotalBalance => "TotalBalance".to_string(),
            StoreKey::LatestTimestamp => "LatestTimestamp".to_string(),
            StoreKey::LatestBlockNumber => "LatestBlockNumber".to_string(),
            StoreKey::TokenBalance => "TokenBalance".to_string(),
            StoreKey::Token0Balance => "Token0Balance".to_string(),
            StoreKey::Token1Balance => "Token1Balance".to_string(),
            StoreKey::OutputTokenBalance => "OutputTokenBalance".to_string(),
            StoreKey::TotalValueLockedUSD => "TotalValueLockedUSD".to_string(),
            StoreKey::TokenPrice => "TokenPrice".to_string(),
            StoreKey::Volume => "Volume".to_string(),
        }
    }
}
