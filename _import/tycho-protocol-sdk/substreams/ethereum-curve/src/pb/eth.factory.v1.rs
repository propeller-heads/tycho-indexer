// @generated
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Pools {
    #[prost(message, repeated, tag="1")]
    pub pools: ::prost::alloc::vec::Vec<Pool>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Pool {
    #[prost(bytes="vec", tag="1")]
    pub pool_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(fixed64, tag="2")]
    pub log_ordinal: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Transfer {
    #[prost(bytes="vec", tag="1")]
    pub from: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="2")]
    pub to: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag="3")]
    pub token: ::prost::alloc::string::String,
    #[prost(string, tag="4")]
    pub amount: ::prost::alloc::string::String,
}
// @@protoc_insertion_point(module)
