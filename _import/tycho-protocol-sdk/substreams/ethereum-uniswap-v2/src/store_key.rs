#[derive(Clone)]
pub enum StoreKey {
    Pool,
}

impl StoreKey {
    pub fn get_unique_pool_key(&self, key: &str) -> String {
        format!("{prefix}:{key}", prefix = self.unique_id())
    }

    pub fn unique_id(&self) -> String {
        match self {
            StoreKey::Pool => "Pool".to_string(),
        }
    }
}
