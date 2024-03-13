use crate::pb::tycho::evm::v1::Transaction;

/// This struct purely exists to spoof the `PartialEq` trait for `Transaction` so we can use it in
///  a later groupby operation.
#[derive(Debug)]
pub struct TransactionWrapper(Transaction);

impl TransactionWrapper {
    pub fn new(tx: Transaction) -> Self {
        Self(tx)
    }
}

impl PartialEq for TransactionWrapper {
    fn eq(&self, other: &Self) -> bool {
        self.0.hash == other.0.hash
    }
}

impl From<TransactionWrapper> for Transaction {
    fn from(value: TransactionWrapper) -> Self {
        value.0
    }
}
