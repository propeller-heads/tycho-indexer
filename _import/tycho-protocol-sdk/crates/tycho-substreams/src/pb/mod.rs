// @generated
pub mod tycho {
    pub mod evm {
        // @@protoc_insertion_point(attribute:tycho.evm.v1)
        pub mod v1 {
            include!("tycho.evm.v1.rs");
            // @@protoc_insertion_point(tycho.evm.v1)

            impl TransactionContractChanges {
                pub fn new(tx: &Transaction) -> Self {
                    Self {
                        tx: Some(tx.clone()),
                        contract_changes: vec![],
                        component_changes: vec![],
                        balance_changes: vec![],
                    }
                }
            }
        }
    }
}
