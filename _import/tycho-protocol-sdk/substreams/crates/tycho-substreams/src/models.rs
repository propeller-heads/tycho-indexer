use substreams_ethereum::pb::eth::v2::{self as sf};

// re-export the protobuf types here.
pub use crate::pb::tycho::evm::v1::*;

impl TransactionContractChanges {
    /// Creates a new empty `TransactionContractChanges` instance.
    pub fn new(tx: &Transaction) -> Self {
        Self { tx: Some(tx.clone()), ..Default::default() }
    }
}

impl TransactionChanges {
    /// Creates a new empty `TransactionChanges` instance.
    pub fn new(tx: &Transaction) -> Self {
        Self { tx: Some(tx.clone()), ..Default::default() }
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
    /// Constructs a new, empty `ProtocolComponent`.
    ///
    /// Initializes an instance with default values. Use `with_*` methods to populate fields
    /// conveniently.
    ///
    /// ## Parameters
    /// - `id`: Identifier for the component.
    /// - `tx`: Reference to the associated transaction.
    pub fn new(id: &str, tx: &Transaction) -> Self {
        Self {
            id: id.to_string(),
            tokens: Vec::new(),
            contracts: Vec::new(),
            static_att: Vec::new(),
            change: ChangeType::Creation.into(),
            protocol_type: None,
            tx: Some(tx.clone()),
        }
    }

    /// Initializes a `ProtocolComponent` with a direct association to a contract.
    ///
    /// Sets the component's ID to the hex-encoded address with a `0x` prefix and includes the
    /// contract in the contracts list.
    ///
    /// ## Parameters
    /// - `id`: Contract address to be encoded and set as the component's ID.
    /// - `tx`: Reference to the associated transaction.
    pub fn at_contract(id: &[u8], tx: &Transaction) -> Self {
        Self {
            id: format!("0x{}", hex::encode(id)),
            tokens: Vec::new(),
            contracts: vec![id.to_vec()],
            static_att: Vec::new(),
            change: ChangeType::Creation.into(),
            protocol_type: None,
            tx: Some(tx.clone()),
        }
    }

    /// Updates the tokens associated with this component.
    ///
    /// ## Parameters
    /// - `tokens`: Slice of byte slices representing the tokens to associate.
    pub fn with_tokens<B: AsRef<[u8]>>(mut self, tokens: &[B]) -> Self {
        self.tokens = tokens
            .iter()
            .map(|e| e.as_ref().to_vec())
            .collect::<Vec<Vec<u8>>>();
        self
    }

    /// Updates the contracts associated with this component.
    ///
    /// ## Parameters
    /// - `contracts`: Slice of byte slices representing the contracts to associate.
    pub fn with_contracts<B: AsRef<[u8]>>(mut self, contracts: &[B]) -> Self {
        self.contracts = contracts
            .iter()
            .map(|e| e.as_ref().to_vec())
            .collect::<Vec<Vec<u8>>>();
        self
    }

    /// Updates the static attributes of this component.
    ///
    /// Sets the change type to `Creation` for all attributes.
    ///
    /// ## Parameters
    /// - `attributes`: Slice of key-value pairs representing the attributes to set.
    pub fn with_attributes<K: AsRef<str>, V: AsRef<[u8]>>(mut self, attributes: &[(K, V)]) -> Self {
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

    /// Designates this component as a swap type within the protocol.
    ///
    /// Sets the `protocol_type` accordingly, including `financial_type` as `Swap` and leaving
    /// `attribute_schema` empty.
    ///
    /// ## Parameters
    /// - `name`: The name of the swap protocol.
    /// - `implementation_type`: The implementation type of the protocol.
    pub fn as_swap_type(mut self, name: &str, implementation_type: ImplementationType) -> Self {
        self.protocol_type = Some(ProtocolType {
            name: name.to_string(),
            financial_type: FinancialType::Swap.into(),
            attribute_schema: Vec::new(),
            implementation_type: implementation_type.into(),
        });
        self
    }
}
