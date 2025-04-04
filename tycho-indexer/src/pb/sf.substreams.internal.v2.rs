// @generated
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ModuleOutput {
    #[prost(string, tag="1")]
    pub module_name: ::prost::alloc::string::String,
    #[prost(string, repeated, tag="4")]
    pub logs: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(bool, tag="5")]
    pub debug_logs_truncated: bool,
    #[prost(bool, tag="6")]
    pub cached: bool,
    #[prost(oneof="module_output::Data", tags="2, 3")]
    pub data: ::core::option::Option<module_output::Data>,
}
/// Nested message and enum types in `ModuleOutput`.
pub mod module_output {
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Data {
        #[prost(message, tag="2")]
        MapOutput(::prost_types::Any),
        #[prost(message, tag="3")]
        StoreDeltas(super::super::super::v1::StoreDeltas),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operations {
    #[prost(message, repeated, tag="1")]
    pub operations: ::prost::alloc::vec::Vec<Operation>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Operation {
    #[prost(enumeration="operation::Type", tag="1")]
    pub r#type: i32,
    #[prost(uint64, tag="2")]
    pub ord: u64,
    #[prost(string, tag="3")]
    pub key: ::prost::alloc::string::String,
    #[prost(bytes="vec", tag="4")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
/// Nested message and enum types in `Operation`.
pub mod operation {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Type {
        Set = 0,
        SetBytes = 1,
        SetIfNotExists = 2,
        SetBytesIfNotExists = 3,
        Append = 4,
        DeletePrefix = 5,
        SetMaxBigInt = 6,
        SetMaxInt64 = 7,
        SetMaxFloat64 = 8,
        SetMaxBigDecimal = 9,
        SetMinBigInt = 10,
        SetMinInt64 = 11,
        SetMinFloat64 = 12,
        SetMinBigDecimal = 13,
        SumBigInt = 14,
        SumInt64 = 15,
        SumFloat64 = 16,
        SumBigDecimal = 17,
        SetSumInt64 = 18,
        SetSumFloat64 = 19,
        SetSumBigInt = 20,
        SetSumBigDecimal = 21,
    }
    impl Type {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Type::Set => "SET",
                Type::SetBytes => "SET_BYTES",
                Type::SetIfNotExists => "SET_IF_NOT_EXISTS",
                Type::SetBytesIfNotExists => "SET_BYTES_IF_NOT_EXISTS",
                Type::Append => "APPEND",
                Type::DeletePrefix => "DELETE_PREFIX",
                Type::SetMaxBigInt => "SET_MAX_BIG_INT",
                Type::SetMaxInt64 => "SET_MAX_INT64",
                Type::SetMaxFloat64 => "SET_MAX_FLOAT64",
                Type::SetMaxBigDecimal => "SET_MAX_BIG_DECIMAL",
                Type::SetMinBigInt => "SET_MIN_BIG_INT",
                Type::SetMinInt64 => "SET_MIN_INT64",
                Type::SetMinFloat64 => "SET_MIN_FLOAT64",
                Type::SetMinBigDecimal => "SET_MIN_BIG_DECIMAL",
                Type::SumBigInt => "SUM_BIG_INT",
                Type::SumInt64 => "SUM_INT64",
                Type::SumFloat64 => "SUM_FLOAT64",
                Type::SumBigDecimal => "SUM_BIG_DECIMAL",
                Type::SetSumInt64 => "SET_SUM_INT64",
                Type::SetSumFloat64 => "SET_SUM_FLOAT64",
                Type::SetSumBigInt => "SET_SUM_BIG_INT",
                Type::SetSumBigDecimal => "SET_SUM_BIG_DECIMAL",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "SET" => Some(Self::Set),
                "SET_BYTES" => Some(Self::SetBytes),
                "SET_IF_NOT_EXISTS" => Some(Self::SetIfNotExists),
                "SET_BYTES_IF_NOT_EXISTS" => Some(Self::SetBytesIfNotExists),
                "APPEND" => Some(Self::Append),
                "DELETE_PREFIX" => Some(Self::DeletePrefix),
                "SET_MAX_BIG_INT" => Some(Self::SetMaxBigInt),
                "SET_MAX_INT64" => Some(Self::SetMaxInt64),
                "SET_MAX_FLOAT64" => Some(Self::SetMaxFloat64),
                "SET_MAX_BIG_DECIMAL" => Some(Self::SetMaxBigDecimal),
                "SET_MIN_BIG_INT" => Some(Self::SetMinBigInt),
                "SET_MIN_INT64" => Some(Self::SetMinInt64),
                "SET_MIN_FLOAT64" => Some(Self::SetMinFloat64),
                "SET_MIN_BIG_DECIMAL" => Some(Self::SetMinBigDecimal),
                "SUM_BIG_INT" => Some(Self::SumBigInt),
                "SUM_INT64" => Some(Self::SumInt64),
                "SUM_FLOAT64" => Some(Self::SumFloat64),
                "SUM_BIG_DECIMAL" => Some(Self::SumBigDecimal),
                "SET_SUM_INT64" => Some(Self::SetSumInt64),
                "SET_SUM_FLOAT64" => Some(Self::SetSumFloat64),
                "SET_SUM_BIG_INT" => Some(Self::SetSumBigInt),
                "SET_SUM_BIG_DECIMAL" => Some(Self::SetSumBigDecimal),
                _ => None,
            }
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProcessRangeRequest {
    #[deprecated]
    #[prost(uint64, tag="2")]
    pub stop_block_num: u64,
    #[prost(string, tag="3")]
    pub output_module: ::prost::alloc::string::String,
    #[prost(message, optional, tag="4")]
    pub modules: ::core::option::Option<super::super::v1::Modules>,
    /// 0-based index of stage to execute up to
    #[prost(uint32, tag="5")]
    pub stage: u32,
    #[prost(string, tag="6")]
    pub metering_config: ::prost::alloc::string::String,
    /// first block that can be streamed on that chain
    #[prost(uint64, tag="7")]
    pub first_streamable_block: u64,
    /// TODO: rename to `wasm_extension_configs`
    #[prost(map="string, string", tag="9")]
    pub wasm_extension_configs: ::std::collections::HashMap<::prost::alloc::string::String, ::prost::alloc::string::String>,
    /// store to use for merged blocks
    #[prost(string, tag="10")]
    pub merged_blocks_store: ::prost::alloc::string::String,
    /// store to use for substreams state
    #[prost(string, tag="11")]
    pub state_store: ::prost::alloc::string::String,
    /// default tag to use for state store
    #[prost(string, tag="12")]
    pub state_store_default_tag: ::prost::alloc::string::String,
    /// number of blocks to process in a single batch
    #[prost(uint64, tag="13")]
    pub segment_size: u64,
    /// block type to process
    #[prost(string, tag="14")]
    pub block_type: ::prost::alloc::string::String,
    /// segment_number * segment_size = start_block_num
    #[prost(uint64, tag="15")]
    pub segment_number: u64,
    /// Whether the tier1 initial request was in production mode or in development mode.
    /// It's possible to have tier2 requests in development mode, for example if the Substreams
    /// needs to back process stores while in development mode.
    #[prost(bool, tag="16")]
    pub production_mode: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProcessRangeResponse {
    #[prost(oneof="process_range_response::Type", tags="4, 5, 6")]
    pub r#type: ::core::option::Option<process_range_response::Type>,
}
/// Nested message and enum types in `ProcessRangeResponse`.
pub mod process_range_response {
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Type {
        #[prost(message, tag="4")]
        Failed(super::Failed),
        #[prost(message, tag="5")]
        Completed(super::Completed),
        #[prost(message, tag="6")]
        Update(super::Update),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Update {
    #[prost(uint64, tag="1")]
    pub duration_ms: u64,
    #[prost(uint64, tag="2")]
    pub processed_blocks: u64,
    #[prost(uint64, tag="3")]
    pub total_bytes_read: u64,
    #[prost(uint64, tag="4")]
    pub total_bytes_written: u64,
    #[prost(message, repeated, tag="5")]
    pub modules_stats: ::prost::alloc::vec::Vec<ModuleStats>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ModuleStats {
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    #[prost(uint64, tag="2")]
    pub processing_time_ms: u64,
    #[prost(uint64, tag="3")]
    pub store_operation_time_ms: u64,
    #[prost(uint64, tag="4")]
    pub store_read_count: u64,
    #[prost(message, repeated, tag="5")]
    pub external_call_metrics: ::prost::alloc::vec::Vec<ExternalCallMetric>,
    /// store-specific (will be 0 on mappers)
    #[prost(uint64, tag="10")]
    pub store_write_count: u64,
    #[prost(uint64, tag="11")]
    pub store_deleteprefix_count: u64,
    #[prost(uint64, tag="12")]
    pub store_size_bytes: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExternalCallMetric {
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    #[prost(uint64, tag="2")]
    pub count: u64,
    #[prost(uint64, tag="3")]
    pub time_ms: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Completed {
    #[prost(message, repeated, tag="1")]
    pub all_processed_ranges: ::prost::alloc::vec::Vec<BlockRange>,
    /// TraceId represents the producer's trace id that produced the partial files.
    /// This is present here so that the consumer can use it to identify the
    /// right partial files that needs to be squashed together.
    ///
    /// The TraceId can be empty in which case it should be assumed by the tier1
    /// consuming this message that the tier2 that produced those partial files
    /// is not yet updated to produce a trace id and a such, the tier1 should
    /// generate a legacy partial file name.
    #[prost(string, tag="2")]
    pub trace_id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Failed {
    #[prost(string, tag="1")]
    pub reason: ::prost::alloc::string::String,
    #[prost(string, repeated, tag="2")]
    pub logs: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// FailureLogsTruncated is a flag that tells you if you received all the logs or if they
    /// were truncated because you logged too much (fixed limit currently is set to 128 KiB).
    #[prost(bool, tag="3")]
    pub logs_truncated: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockRange {
    #[prost(uint64, tag="2")]
    pub start_block: u64,
    #[prost(uint64, tag="3")]
    pub end_block: u64,
}
/// Possible types of WASM modules
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum WasmModuleType {
    Unspecified = 0,
    RpcCall = 1,
}
impl WasmModuleType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            WasmModuleType::Unspecified => "WASM_MODULE_TYPE_UNSPECIFIED",
            WasmModuleType::RpcCall => "WASM_MODULE_TYPE_RPC_CALL",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "WASM_MODULE_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
            "WASM_MODULE_TYPE_RPC_CALL" => Some(Self::RpcCall),
            _ => None,
        }
    }
}
include!("sf.substreams.internal.v2.tonic.rs");
// @@protoc_insertion_point(module)