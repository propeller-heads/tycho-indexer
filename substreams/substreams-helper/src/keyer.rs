pub fn chainlink_asset_key(asset_address: &String) -> String {
    format!("chainlink_price:{}", asset_address)
}
