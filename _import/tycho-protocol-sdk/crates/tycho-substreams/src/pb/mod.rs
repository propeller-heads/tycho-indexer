// @generated
pub mod tycho {
    pub mod evm {
        // @@protoc_insertion_point(attribute:tycho.evm.v1)
        pub mod v1 {
            use substreams_ethereum::pb::eth::v2::{self as sf};
            include!("tycho.evm.v1.rs");
            // @@protoc_insertion_point(tycho.evm.v1)

            impl TransactionContractChanges {
                /// Creates a new empty `TransactionContractChanges` instance.
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
                /// Creates a new empty `ProtocolComponent` instance.
                ///
                /// You can use the `with_*` methods to set the fields in a convience way.
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

                /// Shorthand to create a component with a 1-1 relationship to a contract.
                ///
                /// Will set the component id to a hex encoded address with a 0x prefix
                /// and add the contract to contracts attributes.
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

                /// Replaces the tokens on this component.
                pub fn with_tokens<B: AsRef<[u8]>>(mut self, tokens: &[B]) -> Self {
                    self.tokens = tokens
                        .iter()
                        .map(|e| e.as_ref().to_vec())
                        .collect::<Vec<Vec<u8>>>();
                    self
                }

                /// Replaces the contracts associated with this component.
                pub fn with_contracts<B: AsRef<[u8]>>(mut self, contracts: &[B]) -> Self {
                    self.contracts = contracts
                        .iter()
                        .map(|e| e.as_ref().to_vec())
                        .collect::<Vec<Vec<u8>>>();
                    self
                }

                /// Replaces the static attributes on this component.
                ///
                /// The change type will be set to Creation.
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

                /// Sets the protocol_type on this component.
                ///
                /// Will set the `financial_type` to FinancialType::Swap and the
                /// `attribute_schema` to an empty list.
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
