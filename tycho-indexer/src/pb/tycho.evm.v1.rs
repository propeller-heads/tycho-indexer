// @generated
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Block {
    #[prost(bytes = "vec", tag = "1")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub parent_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub number: u64,
    #[prost(uint64, tag = "4")]
    pub ts: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Transaction {
    #[prost(bytes = "vec", tag = "1")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub from: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub to: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub index: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ContractSlot {
    #[prost(bytes = "vec", tag = "2")]
    pub slot: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ContractChange {
    #[prost(bytes = "vec", tag = "1")]
    pub address: ::prost::alloc::vec::Vec<u8>,
    /// empty bytes indicates no change
    #[prost(bytes = "vec", tag = "2")]
    pub balance: ::prost::alloc::vec::Vec<u8>,
    /// empty bytes indicates no change
    #[prost(bytes = "vec", tag = "3")]
    pub code: ::prost::alloc::vec::Vec<u8>,
    /// empty sequence indicates no change
    #[prost(message, repeated, tag = "4")]
    pub slots: ::prost::alloc::vec::Vec<ContractSlot>,
    /// Whether this is an update, creation or deletion
    #[prost(enumeration = "ChangeType", tag = "5")]
    pub change: i32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProtocolComponent {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub tokens: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(message, repeated, tag = "2")]
    pub contracts: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", tag = "3")]
    pub id: ::prost::alloc::vec::Vec<u8>,
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TvlUpdate {
    #[prost(bytes = "vec", tag = "2")]
    pub token: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub balance: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionChanges {
    #[prost(message, optional, tag = "1")]
    pub tx: ::core::option::Option<Transaction>,
    #[prost(message, repeated, tag = "2")]
    pub contract_changes: ::prost::alloc::vec::Vec<ContractChange>,
    #[prost(message, repeated, tag = "3")]
    pub components: ::prost::alloc::vec::Vec<ProtocolComponent>,
    #[prost(message, repeated, tag = "4")]
    pub tvl: ::prost::alloc::vec::Vec<TvlUpdate>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockContractChanges {
    #[prost(message, optional, tag = "1")]
    pub block: ::core::option::Option<Block>,
    #[prost(message, repeated, tag = "2")]
    pub changes: ::prost::alloc::vec::Vec<TransactionChanges>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ChangeType {
    Unspecified = 0,
    Update = 1,
    Creation = 2,
    Deletion = 3,
}
impl ChangeType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ChangeType::Unspecified => "CHANGE_TYPE_UNSPECIFIED",
            ChangeType::Update => "CHANGE_TYPE_UPDATE",
            ChangeType::Creation => "CHANGE_TYPE_CREATION",
            ChangeType::Deletion => "CHANGE_TYPE_DELETION",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "CHANGE_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
            "CHANGE_TYPE_UPDATE" => Some(Self::Update),
            "CHANGE_TYPE_CREATION" => Some(Self::Creation),
            "CHANGE_TYPE_DELETION" => Some(Self::Deletion),
            _ => None,
        }
    }
}
// @@protoc_insertion_point(module)
