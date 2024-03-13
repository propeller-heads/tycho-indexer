// @generated
pub mod tycho {
    pub mod evm {
        // @@protoc_insertion_point(attribute:tycho.evm.v1)
        pub mod v1 {
            use substreams_ethereum::pb::eth::v2::{self as sf};
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

            impl From<&sf::TransactionTrace> for Transaction {
                fn from(tx: &sf::TransactionTrace) -> Self {
                    Self {
                        hash: tx.hash.clone(),
                        from: tx.from.clone(),
                        to: tx.to.clone(),
                        index: tx.index.into(),
                    }
                }
            }

            impl From<&sf::Block> for Block {
                fn from(block: &sf::Block) -> Self {
                    Self {
                        number: block.number,
                        hash: block.hash.clone(),
                        parent_hash: block
                            .header
                            .as_ref()
                            .expect("Block header not present")
                            .parent_hash
                            .clone(),
                        ts: block.timestamp_seconds(),
                    }
                }
            }

            impl ProtocolComponent {
                pub fn new(id: &str, tx: &Transaction) -> Self {
                    Self {
                        id: id.to_string(),
                        tokens: vec![],
                        contracts: vec![],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: None,
                        tx: Some(tx.clone()),
                    }
                }

                pub fn at_contract(id: &[u8], tx: &Transaction) -> Self {
                    Self {
                        id: format!("0x{}", hex::encode(id)),
                        tokens: vec![],
                        contracts: vec![id.to_vec()],
                        static_att: vec![],
                        change: ChangeType::Creation.into(),
                        protocol_type: None,
                        tx: Some(tx.clone()),
                    }
                }

                pub fn with_tokens<B: AsRef<[u8]>>(mut self, tokens: &[B]) -> Self {
                    self.tokens = tokens
                        .iter()
                        .map(|e| e.as_ref().to_vec())
                        .collect::<Vec<Vec<u8>>>();
                    self
                }

                pub fn with_contracts<B: AsRef<[u8]>>(mut self, contracts: &[B]) -> Self {
                    self.contracts = contracts
                        .iter()
                        .map(|e| e.as_ref().to_vec())
                        .collect::<Vec<Vec<u8>>>();
                    self
                }

                pub fn with_attributes<K: AsRef<str>, V: AsRef<[u8]>>(
                    mut self,
                    attributes: &[(K, V)],
                ) -> Self {
                    self.static_att = attributes
                        .iter()
                        .map(|(k, v)| Attribute {
                            name: k.as_ref().to_string(),
                            value: v.as_ref().to_vec(),
                            change: ChangeType::Creation.into(),
                        })
                        .collect::<Vec<Attribute>>();
                    self
                }

                pub fn as_swap_type(
                    mut self,
                    name: &str,
                    implementation_type: ImplementationType,
                ) -> Self {
                    self.protocol_type = Some(ProtocolType {
                        name: name.to_string(),
                        financial_type: FinancialType::Swap.into(),
                        attribute_schema: vec![],
                        implementation_type: implementation_type.into(),
                    });
                    self
                }
            }
        }
    }
}
