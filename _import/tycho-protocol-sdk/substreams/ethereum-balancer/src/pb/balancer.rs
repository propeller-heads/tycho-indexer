// @generated
/// A struct for following the changes of Total Value Locked (TVL).
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BalanceDelta {
    #[prost(uint64, tag="1")]
    pub ord: u64,
    /// The tx hash of the transaction that caused the balance change.
    #[prost(message, optional, tag="2")]
    pub tx: ::core::option::Option<super::tycho::evm::v1::Transaction>,
    /// The address of the ERC20 token whose balance changed.
    #[prost(bytes="vec", tag="3")]
    pub token: ::prost::alloc::vec::Vec<u8>,
    /// The delta balance of the token.
    #[prost(bytes="vec", tag="4")]
    pub delta: ::prost::alloc::vec::Vec<u8>,
    /// The id of the component whose TVL is tracked.
    /// If the protocol component includes multiple contracts, the balance change must be aggregated to reflect how much tokens can be traded.
    #[prost(bytes="vec", tag="5")]
    pub component_id: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BalanceDeltas {
    #[prost(message, repeated, tag="1")]
    pub balance_deltas: ::prost::alloc::vec::Vec<BalanceDelta>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionProtocolComponents {
    #[prost(message, optional, tag="1")]
    pub tx: ::core::option::Option<super::tycho::evm::v1::Transaction>,
    #[prost(message, repeated, tag="2")]
    pub components: ::prost::alloc::vec::Vec<super::tycho::evm::v1::ProtocolComponent>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GroupedTransactionProtocolComponents {
    #[prost(message, repeated, tag="1")]
    pub tx_components: ::prost::alloc::vec::Vec<TransactionProtocolComponents>,
}
// @@protoc_insertion_point(module)
