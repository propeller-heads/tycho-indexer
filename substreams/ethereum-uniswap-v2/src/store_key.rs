#[derive(Clone)]
pub enum StoreKey {
    Pool,
    LatestTimestamp,
    LatestBlockNumber,
}

impl StoreKey {
    pub fn get_unique_pool_key(&self, key: &str) -> String {
        format!("{}:{}", self.unique_id(), key)
    }

    pub fn get_unique_pair_key(&self, key1: &str, key2: &str) -> String {
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
            StoreKey::LatestTimestamp => "LatestTimestamp".to_string(),
            StoreKey::LatestBlockNumber => "LatestBlockNumber".to_string(),
        }
    }
}
