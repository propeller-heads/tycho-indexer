// @generated
/// A change to a pool's balance. Ambient specific.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AmbientBalanceDelta {
    /// The address of the ERC20 token whose balance changed.
    #[prost(bytes="vec", tag="1")]
    pub pool_hash: ::prost::alloc::vec::Vec<u8>,
    /// The token type: it can be base or quote.
    #[prost(string, tag="2")]
    pub token_type: ::prost::alloc::string::String,
    /// The delta of the token.
    #[prost(bytes="vec", tag="3")]
    pub token_delta: ::prost::alloc::vec::Vec<u8>,
    /// Used to determine the order of the balance changes. Necessary for the balance store.
    #[prost(uint64, tag="4")]
    pub ordinal: u64,
    /// Transaction where the balance changed.
    #[prost(message, optional, tag="5")]
    pub tx: ::core::option::Option<super::super::evm::v1::Transaction>,
}
/// Ambient pool changes within a single block
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockPoolChanges {
    /// New protocol components added in this block
    #[prost(message, repeated, tag="1")]
    pub protocol_components: ::prost::alloc::vec::Vec<super::super::evm::v1::ProtocolComponent>,
    /// Balance changes to pools in this block
    #[prost(message, repeated, tag="2")]
    pub balance_deltas: ::prost::alloc::vec::Vec<AmbientBalanceDelta>,
}
// @@protoc_insertion_point(module)
