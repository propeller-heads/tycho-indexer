// @generated
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SingleBlockRequest {
    #[prost(message, repeated, tag="6")]
    pub transforms: ::prost::alloc::vec::Vec<::prost_types::Any>,
    #[prost(oneof="single_block_request::Reference", tags="3, 4, 5")]
    pub reference: ::core::option::Option<single_block_request::Reference>,
}
/// Nested message and enum types in `SingleBlockRequest`.
pub mod single_block_request {
    /// Get the current known canonical version of a block at with this number
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct BlockNumber {
        #[prost(uint64, tag="1")]
        pub num: u64,
    }
    /// Get the current block with specific hash and number
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct BlockHashAndNumber {
        #[prost(uint64, tag="1")]
        pub num: u64,
        #[prost(string, tag="2")]
        pub hash: ::prost::alloc::string::String,
    }
    /// Get the block that generated a specific cursor
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Cursor {
        #[prost(string, tag="1")]
        pub cursor: ::prost::alloc::string::String,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Reference {
        #[prost(message, tag="3")]
        BlockNumber(BlockNumber),
        #[prost(message, tag="4")]
        BlockHashAndNumber(BlockHashAndNumber),
        #[prost(message, tag="5")]
        Cursor(Cursor),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SingleBlockResponse {
    #[prost(message, optional, tag="1")]
    pub block: ::core::option::Option<::prost_types::Any>,
    /// Metadata about the block, added in some Firehose version, so consumer
    /// should be ready to handle the absence of this field.
    #[prost(message, optional, tag="2")]
    pub metadata: ::core::option::Option<BlockMetadata>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Request {
    /// Controls where the stream of blocks will start.
    ///
    /// The stream will start **inclusively** at the requested block num.
    ///
    /// When not provided, starts at first streamable block of the chain. Not all
    /// chain starts at the same block number, so you might get an higher block than
    /// requested when using default value of 0.
    ///
    /// Can be negative, will be resolved relative to the chain head block, assuming
    /// a chain at head block #100, then using `-50` as the value will start at block
    /// #50. If it resolves before first streamable block of chain, we assume start
    /// of chain.
    ///
    /// If `start_cursor` is given, this value is ignored and the stream instead starts
    /// immediately after the Block pointed by the opaque `start_cursor` value.
    #[prost(int64, tag="1")]
    pub start_block_num: i64,
    /// Controls where the stream of blocks will start which will be immediately after
    /// the Block pointed by this opaque cursor.
    ///
    /// Obtain this value from a previously received `Response.cursor`.
    ///
    /// This value takes precedence over `start_block_num`.
    #[prost(string, tag="2")]
    pub cursor: ::prost::alloc::string::String,
    /// When non-zero, controls where the stream of blocks will stop.
    ///
    /// The stream will close **after** that block has passed so the boundary is
    /// **inclusive**.
    #[prost(uint64, tag="3")]
    pub stop_block_num: u64,
    /// With final_block_only, you only receive blocks with STEP_FINAL
    /// Default behavior will send blocks as STEP_NEW, with occasional STEP_UNDO
    #[prost(bool, tag="4")]
    pub final_blocks_only: bool,
    #[prost(message, repeated, tag="10")]
    pub transforms: ::prost::alloc::vec::Vec<::prost_types::Any>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Response {
    /// Chain specific block payload, ex:
    ///    - sf.eosio.type.v1.Block
    ///    - sf.ethereum.type.v1.Block
    ///    - sf.near.type.v1.Block
    #[prost(message, optional, tag="1")]
    pub block: ::core::option::Option<::prost_types::Any>,
    #[prost(enumeration="ForkStep", tag="6")]
    pub step: i32,
    #[prost(string, tag="10")]
    pub cursor: ::prost::alloc::string::String,
    /// Metadata about the block, added in some Firehose version, so consumer
    /// should be ready to handle the absence of this field.
    #[prost(message, optional, tag="12")]
    pub metadata: ::core::option::Option<BlockMetadata>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockMetadata {
    /// Num is the block number of this response's block.
    #[prost(uint64, tag="1")]
    pub num: u64,
    /// ID is the block ID of this response's block. The ID actual representation is chain specific.
    /// - Antelope & Ethereum uses hex.
    /// - NEAR & Solana uses base58.
    ///
    /// Refer to the chain documentation for more details.
    #[prost(string, tag="2")]
    pub id: ::prost::alloc::string::String,
    /// ParentNum is the block number of the parent of this response's block
    #[prost(uint64, tag="3")]
    pub parent_num: u64,
    /// ParentID is the block ID of the parent of this response's block. If this response is the genesis block,
    /// this field is empty.
    ///
    /// The ID actual representation is chain specific.
    /// - Antelope & Ethereum uses hex.
    /// - NEAR & Solana uses base58.
    ///
    /// Refer to the chain documentation for more details.
    #[prost(string, tag="4")]
    pub parent_id: ::prost::alloc::string::String,
    /// LibNum is the block number of the last irreversible block (a.k.a last finalized block) at the time of this
    /// response' block. It determines the finality of the block.
    #[prost(uint64, tag="5")]
    pub lib_num: u64,
    /// Time is the time at which the block was produced.
    #[prost(message, optional, tag="6")]
    pub time: ::core::option::Option<::prost_types::Timestamp>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InfoRequest {
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InfoResponse {
    /// Canonical chain name from <https://thegraph.com/docs/en/developing/supported-networks/> (ex: matic, mainnet ...)
    #[prost(string, tag="1")]
    pub chain_name: ::prost::alloc::string::String,
    /// Alternate names for the chain.
    #[prost(string, repeated, tag="2")]
    pub chain_name_aliases: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// First block that is served by this endpoint. This should usually be the genesis block, 
    /// but some providers may have truncated history.
    #[prost(uint64, tag="3")]
    pub first_streamable_block_num: u64,
    #[prost(string, tag="4")]
    pub first_streamable_block_id: ::prost::alloc::string::String,
    /// This informs the client on how to decode the `block_id` field inside the "Clock" message
    /// as well as the `first_streamable_block_id` above.
    #[prost(enumeration="info_response::BlockIdEncoding", tag="5")]
    pub block_id_encoding: i32,
    /// features describes the blocks. Popular values for EVM chains include `base`, `extended` or `hybrid`.
    #[prost(string, repeated, tag="10")]
    pub block_features: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// Nested message and enum types in `InfoResponse`.
pub mod info_response {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum BlockIdEncoding {
        Unset = 0,
        Hex = 1,
        BlockIdEncoding0xHex = 2,
        Base58 = 3,
        Base64 = 4,
        Base64url = 5,
    }
    impl BlockIdEncoding {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                BlockIdEncoding::Unset => "BLOCK_ID_ENCODING_UNSET",
                BlockIdEncoding::Hex => "BLOCK_ID_ENCODING_HEX",
                BlockIdEncoding::BlockIdEncoding0xHex => "BLOCK_ID_ENCODING_0X_HEX",
                BlockIdEncoding::Base58 => "BLOCK_ID_ENCODING_BASE58",
                BlockIdEncoding::Base64 => "BLOCK_ID_ENCODING_BASE64",
                BlockIdEncoding::Base64url => "BLOCK_ID_ENCODING_BASE64URL",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "BLOCK_ID_ENCODING_UNSET" => Some(Self::Unset),
                "BLOCK_ID_ENCODING_HEX" => Some(Self::Hex),
                "BLOCK_ID_ENCODING_0X_HEX" => Some(Self::BlockIdEncoding0xHex),
                "BLOCK_ID_ENCODING_BASE58" => Some(Self::Base58),
                "BLOCK_ID_ENCODING_BASE64" => Some(Self::Base64),
                "BLOCK_ID_ENCODING_BASE64URL" => Some(Self::Base64url),
                _ => None,
            }
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ForkStep {
    StepUnset = 0,
    /// Incoming block
    StepNew = 1,
    /// A reorg caused this specific block to be excluded from the chain
    StepUndo = 2,
    /// Block is now final and can be committed (finality is chain specific,
    /// see chain documentation for more details)
    StepFinal = 3,
}
impl ForkStep {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ForkStep::StepUnset => "STEP_UNSET",
            ForkStep::StepNew => "STEP_NEW",
            ForkStep::StepUndo => "STEP_UNDO",
            ForkStep::StepFinal => "STEP_FINAL",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "STEP_UNSET" => Some(Self::StepUnset),
            "STEP_NEW" => Some(Self::StepNew),
            "STEP_UNDO" => Some(Self::StepUndo),
            "STEP_FINAL" => Some(Self::StepFinal),
            _ => None,
        }
    }
}
include!("sf.firehose.v2.tonic.rs");
// @@protoc_insertion_point(module)