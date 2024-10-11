pub mod account_extractor;
pub mod token_analyzer;
pub mod token_pre_processor;

use ethers::{
    providers::ProviderError,
    types::{H160, H256, U256},
};
use thiserror::Error;
use tycho_core::{models::blockchain::BlockTag, Bytes};
use web3::types::BlockNumber;

#[derive(Error, Debug)]
pub enum RPCError {
    #[error("RPC setup error: {0}")]
    SetupError(String),
    #[error("RPC error: {0}")]
    RequestError(#[from] ProviderError),
}

pub struct BlockTagWrapper(BlockTag);

impl From<BlockTagWrapper> for BlockNumber {
    fn from(value: BlockTagWrapper) -> Self {
        match value.0 {
            BlockTag::Finalized => BlockNumber::Finalized,
            BlockTag::Safe => BlockNumber::Safe,
            BlockTag::Latest => BlockNumber::Latest,
            BlockTag::Earliest => BlockNumber::Earliest,
            BlockTag::Pending => BlockNumber::Pending,
            BlockTag::Number(n) => BlockNumber::Number(n.into()),
        }
    }
}

/// A trait for converting types to and from `Bytes`.
///
/// This trait provides methods to convert a type into a `Bytes` object,
/// as well as reconstruct the original type from a `Bytes` object.
///
/// # Examples
/// ```
/// let h160_value: H160 = ...;
/// let bytes: Bytes = h160_value.to_bytes(); // Converts H160 to Bytes
/// let new_h160 = H160::from_bytes(bytes);   // Converts Bytes back to H160
/// ```
pub trait BytesConvertible {
    /// Converts the current type into a `Bytes` object.
    fn to_bytes(self) -> Bytes;

    /// Reconstructs the type from a `Bytes` object.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The `Bytes` object to convert into the original type.
    ///
    /// # Returns
    ///
    /// The type that was converted from `Bytes`.
    fn from_bytes(bytes: &Bytes) -> Self;
}

// Implementing `BytesConvertible` for `H160`.
impl BytesConvertible for H160 {
    /// Converts `H160` to `Bytes`.
    fn to_bytes(self) -> Bytes {
        Bytes::from(self.0.to_vec())
    }

    /// Converts `Bytes` to `H160`.
    ///
    /// # Panics
    ///
    /// Will panic if the length of `Bytes` is not 20 (which is the size of an `H160`).
    fn from_bytes(bytes: &Bytes) -> Self {
        H160::from_slice(bytes.as_ref())
    }
}

// Implementing `BytesConvertible` for `H256`.
impl BytesConvertible for H256 {
    /// Converts `H256` to `Bytes`.
    fn to_bytes(self) -> Bytes {
        Bytes::from(self.0.to_vec())
    }

    /// Converts `Bytes` to `H256`.
    ///
    /// # Panics
    ///
    /// Will panic if the length of `Bytes` is not 32 (which is the size of an `H256`).
    fn from_bytes(bytes: &Bytes) -> Self {
        H256::from_slice(bytes.as_ref())
    }
}

// Implementing `BytesConvertible` for `U256`.
impl BytesConvertible for U256 {
    /// Converts `U256` to `Bytes`.
    fn to_bytes(self) -> Bytes {
        let mut buf = [0u8; 32];
        self.to_big_endian(&mut buf);
        Bytes::from(buf.to_vec())
    }

    /// Converts `Bytes` to `U256`.
    ///
    /// # Panics
    ///
    /// Will panic if the length of `Bytes` is larger than 32.
    fn from_bytes(bytes: &Bytes) -> Self {
        let bytes_slice = bytes.as_ref();

        // Create an array with zeros.
        let mut u256_bytes: [u8; 32] = [0; 32];

        // Copy bytes from `bytes_slice` to `u256_bytes`.
        u256_bytes[..bytes_slice.len()].copy_from_slice(bytes_slice);

        // Convert the byte array to `U256` using little-endian.
        U256::from_little_endian(&u256_bytes)
    }
}
