use substreams_ethereum::pb::eth::v2::StorageChange;

pub trait StorageChangesFilter {
    fn filter_by_address(&self, contract_addr: &[u8; 20]) -> Vec<&StorageChange>;
}

impl StorageChangesFilter for Vec<StorageChange> {
    fn filter_by_address(&self, contract_addr: &[u8; 20]) -> Vec<&StorageChange> {
        self.iter()
            .filter(|change| change.address == contract_addr)
            .collect()
    }
}
