// @generated
/// Copy of tycho.evm.v1.Transaction to be able to implement conversions to/from TransactionTrace
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Transaction {
    #[prost(bytes="vec", tag="1")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="2")]
    pub from: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="3")]
    pub to: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag="4")]
    pub index: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TickDelta {
    /// bytes32
    #[prost(bytes="vec", tag="1")]
    pub pool_id: ::prost::alloc::vec::Vec<u8>,
    #[prost(int32, tag="2")]
    pub tick_index: i32,
    /// int128
    #[prost(bytes="vec", tag="3")]
    pub liquidity_net_delta: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag="4")]
    pub ordinal: u64,
    #[prost(message, optional, tag="5")]
    pub transaction: ::core::option::Option<Transaction>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TickDeltas {
    #[prost(message, repeated, tag="1")]
    pub deltas: ::prost::alloc::vec::Vec<TickDelta>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LiquidityChange {
    /// bytes32
    #[prost(bytes="vec", tag="1")]
    pub pool_id: ::prost::alloc::vec::Vec<u8>,
    /// uint128 or int128, depending on change_type
    #[prost(bytes="vec", tag="2")]
    pub value: ::prost::alloc::vec::Vec<u8>,
    #[prost(enumeration="LiquidityChangeType", tag="3")]
    pub change_type: i32,
    #[prost(uint64, tag="4")]
    pub ordinal: u64,
    #[prost(message, optional, tag="5")]
    pub transaction: ::core::option::Option<Transaction>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LiquidityChanges {
    #[prost(message, repeated, tag="1")]
    pub changes: ::prost::alloc::vec::Vec<LiquidityChange>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PoolDetails {
    /// address
    #[prost(bytes="vec", tag="1")]
    pub token0: ::prost::alloc::vec::Vec<u8>,
    /// address
    #[prost(bytes="vec", tag="2")]
    pub token1: ::prost::alloc::vec::Vec<u8>,
    #[prost(fixed64, tag="3")]
    pub fee: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockTransactionEvents {
    #[prost(message, repeated, tag="1")]
    pub block_transaction_events: ::prost::alloc::vec::Vec<block_transaction_events::TransactionEvents>,
}
/// Nested message and enum types in `BlockTransactionEvents`.
pub mod block_transaction_events {
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct TransactionEvents {
        #[prost(message, optional, tag="1")]
        pub transaction: ::core::option::Option<super::Transaction>,
        #[prost(message, repeated, tag="2")]
        pub pool_logs: ::prost::alloc::vec::Vec<transaction_events::PoolLog>,
    }
    /// Nested message and enum types in `TransactionEvents`.
    pub mod transaction_events {
        #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
        pub struct PoolLog {
            #[prost(uint64, tag="1")]
            pub ordinal: u64,
            /// bytes32
            #[prost(bytes="vec", tag="2")]
            pub pool_id: ::prost::alloc::vec::Vec<u8>,
            #[prost(oneof="pool_log::Event", tags="3, 4, 5, 6, 7")]
            pub event: ::core::option::Option<pool_log::Event>,
        }
        /// Nested message and enum types in `PoolLog`.
        pub mod pool_log {
            #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
            pub struct Swapped {
                /// int128
                #[prost(bytes="vec", tag="1")]
                pub delta0: ::prost::alloc::vec::Vec<u8>,
                /// int128
                #[prost(bytes="vec", tag="2")]
                pub delta1: ::prost::alloc::vec::Vec<u8>,
                /// uint192
                #[prost(bytes="vec", tag="3")]
                pub sqrt_ratio_after: ::prost::alloc::vec::Vec<u8>,
                /// uint128
                #[prost(bytes="vec", tag="4")]
                pub liquidity_after: ::prost::alloc::vec::Vec<u8>,
                /// int32
                #[prost(sint32, tag="5")]
                pub tick_after: i32,
            }
            #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
            pub struct PositionUpdated {
                /// int32
                #[prost(sint32, tag="1")]
                pub lower: i32,
                /// int32
                #[prost(sint32, tag="2")]
                pub upper: i32,
                /// int128
                #[prost(bytes="vec", tag="3")]
                pub liquidity_delta: ::prost::alloc::vec::Vec<u8>,
                /// int128
                #[prost(bytes="vec", tag="4")]
                pub delta0: ::prost::alloc::vec::Vec<u8>,
                /// int128
                #[prost(bytes="vec", tag="5")]
                pub delta1: ::prost::alloc::vec::Vec<u8>,
            }
            #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
            pub struct PositionFeesCollected {
                /// uint128
                #[prost(bytes="vec", tag="1")]
                pub amount0: ::prost::alloc::vec::Vec<u8>,
                /// uint128
                #[prost(bytes="vec", tag="2")]
                pub amount1: ::prost::alloc::vec::Vec<u8>,
            }
            #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
            pub struct PoolInitialized {
                /// address
                #[prost(bytes="vec", tag="1")]
                pub token0: ::prost::alloc::vec::Vec<u8>,
                /// address
                #[prost(bytes="vec", tag="2")]
                pub token1: ::prost::alloc::vec::Vec<u8>,
                /// bytes32
                #[prost(bytes="vec", tag="3")]
                pub config: ::prost::alloc::vec::Vec<u8>,
                /// int32
                #[prost(sint32, tag="4")]
                pub tick: i32,
                /// uint192
                #[prost(bytes="vec", tag="5")]
                pub sqrt_ratio: ::prost::alloc::vec::Vec<u8>,
                #[prost(enumeration="pool_initialized::Extension", tag="6")]
                pub extension: i32,
            }
            /// Nested message and enum types in `PoolInitialized`.
            pub mod pool_initialized {
                #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
                #[repr(i32)]
                pub enum Extension {
                    Unknown = 0,
                    Base = 1,
                    Oracle = 2,
                }
                impl Extension {
                    /// String value of the enum field names used in the ProtoBuf definition.
                    ///
                    /// The values are not transformed in any way and thus are considered stable
                    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
                    pub fn as_str_name(&self) -> &'static str {
                        match self {
                            Extension::Unknown => "EXTENSION_UNKNOWN",
                            Extension::Base => "EXTENSION_BASE",
                            Extension::Oracle => "EXTENSION_ORACLE",
                        }
                    }
                    /// Creates an enum from field names used in the ProtoBuf definition.
                    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
                        match value {
                            "EXTENSION_UNKNOWN" => Some(Self::Unknown),
                            "EXTENSION_BASE" => Some(Self::Base),
                            "EXTENSION_ORACLE" => Some(Self::Oracle),
                            _ => None,
                        }
                    }
                }
            }
            #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
            pub struct FeesAccumulated {
                /// uint128
                #[prost(bytes="vec", tag="1")]
                pub amount0: ::prost::alloc::vec::Vec<u8>,
                /// uint128
                #[prost(bytes="vec", tag="2")]
                pub amount1: ::prost::alloc::vec::Vec<u8>,
            }
            #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Oneof)]
            pub enum Event {
                #[prost(message, tag="3")]
                Swapped(Swapped),
                #[prost(message, tag="4")]
                PositionUpdated(PositionUpdated),
                #[prost(message, tag="5")]
                PositionFeesCollected(PositionFeesCollected),
                #[prost(message, tag="6")]
                PoolInitialized(PoolInitialized),
                #[prost(message, tag="7")]
                FeesAccumulated(FeesAccumulated),
            }
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum LiquidityChangeType {
    Delta = 0,
    Absolute = 1,
}
impl LiquidityChangeType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            LiquidityChangeType::Delta => "DELTA",
            LiquidityChangeType::Absolute => "ABSOLUTE",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "DELTA" => Some(Self::Delta),
            "ABSOLUTE" => Some(Self::Absolute),
            _ => None,
        }
    }
}
// @@protoc_insertion_point(module)
