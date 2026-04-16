// @generated
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Request {
    /// if positive, determines the absolute requested start block
    /// if 0, the start block is determined by the chain's first streamable block
    /// if negative, the start block is relative to the chain HEAD (determined server-side at the time of the request)
    #[prost(int64, tag="1")]
    pub start_block_num: i64,
    /// start_cursor has precedence over start_block_num
    #[prost(string, tag="2")]
    pub start_cursor: ::prost::alloc::string::String,
    /// if non-zero, processing will stop *before* this block (exclusive)
    /// if zero, processing will continue and keep up with the chain HEAD
    #[prost(uint64, tag="3")]
    pub stop_block_num: u64,
    /// With final_block_only, you only receive blocks that are irreversible:
    /// 'final_block_height' will be equal to current block and no 'undo_signal' will ever be sent
    #[prost(bool, tag="4")]
    pub final_blocks_only: bool,
    /// Substreams has two mode when executing your module(s) either development mode or production
    /// mode. Development and production modes impact the execution of Substreams, important aspects
    /// of execution include:
    /// * The time required to reach the first byte.
    /// * The speed that large ranges get executed.
    /// * The module logs and outputs sent back to the client.
    ///
    /// By default, the engine runs in developer mode, with richer and deeper output. Differences
    /// between production and development modes include:
    /// * Forward parallel execution is enabled in production mode and disabled in development mode
    /// * The time required to reach the first byte in development mode is faster than in production mode.
    ///
    /// Specific attributes of development mode include:
    /// * The client will receive all of the executed module's logs.
    /// * It's possible to request specific store snapshots in the execution tree (via `debug_initial_store_snapshot_for_modules`).
    /// * Multiple module's output is possible.
    ///
    /// With production mode`, however, you trade off functionality for high speed enabling forward
    /// parallel execution of module ahead of time.
    #[prost(bool, tag="5")]
    pub production_mode: bool,
    #[prost(string, tag="6")]
    pub output_module: ::prost::alloc::string::String,
    /// whole spkg package
    #[prost(message, optional, tag="7")]
    pub package: ::core::option::Option<super::super::v1::Package>,
    /// params applied over the package
    #[prost(map="string, string", tag="8")]
    pub params: ::std::collections::HashMap<::prost::alloc::string::String, ::prost::alloc::string::String>,
    /// network choice applied over the package
    #[prost(string, tag="9")]
    pub network: ::prost::alloc::string::String,
    /// Available only in developer mode
    #[prost(string, repeated, tag="10")]
    pub debug_initial_store_snapshot_for_modules: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// Prepares the stores and caches on the server, sending only progress messages and "minimal" clock data (and cursor)
    #[prost(bool, tag="11")]
    pub noop_mode: bool,
    /// If set, the engine will reject a request if the number of blocks to process (including preparing the stores) is above this limit.
    /// Useful as a safeguard for managing costs
    #[prost(uint64, tag="12")]
    pub limit_processed_blocks: u64,
    /// Available only in developer mode
    /// If set, the server will only send the output of these modules.
    /// If unset, all the outputs are sent.
    /// This allows the user to reduce the payload in dev mode, while still getting some extra debugging information
    #[prost(string, repeated, tag="13")]
    pub dev_output_modules: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// Progress_messages_interval_ms is the interval between progress messages, in milliseconds (min 500ms)
    /// default: start at 500ms and ramp up to 5000ms within 1min
    #[prost(uint64, tag="14")]
    pub progress_messages_interval_ms: u64,
    /// If true, blocks close to head will be sent in "partials" as soon as we get them.
    /// This means that you will get different versions of the same block number, each an incomplete increment
    /// Other blocks will be sent completely (older blocks, or blocks for which the provider did not get a partial in time)
    #[prost(bool, tag="16")]
    pub partial_blocks: bool,
}
include!("sf.substreams.rpc.v3.tonic.rs");
// @@protoc_insertion_point(module)