use downcast_rs::{impl_downcast, Downcast};
use ethabi::ethereum_types::Address;
use substreams::scalar::BigInt;
use substreams_ethereum::pb::eth as pbeth;
use tiny_keccak::{Hasher, Keccak};

use crate::common::HasAddresser;
use crate::errors::StorageDecodingError;
use crate::math::NumberModulo;

pub const SLOT_SIZE: usize = 32;

/// A convenience struct that puts together each storage change with its keccak preimage.
/// Only applies to storage changes in hashed keys (like mappings, arrays, etc).
/// Otherwise, preimage will be `None`.
#[derive(Debug, Clone)]
pub struct StorageChange {
    pub change: pbeth::v2::StorageChange,
    pub preimage: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct KeccakPreimage {
    pub preimage: Vec<u8>,
    pub slot: BigInt,
}

/// StorageLayout is trait to normalize the decoding of raw storage slots into their own
/// respective types.
pub trait StorageLayout: Downcast {
    /// Returns the size in bytes of this type. In the case of structs, this is the sum of all the slots
    /// the struct takes, not only the raw addition of its underlying types.
    fn size(&self) -> usize;
    /// Will attempt to decode a set of slots into the given type. For types that can be offseted inside a slot,
    /// there is an optional offset parameter. This will be ignored by arrays, mappings and structs.
    fn decode(
        &mut self,
        slots: Vec<Vec<u8>>,
        offset: Option<usize>,
    ) -> Result<(), StorageDecodingError>;

    /// Sets the slot for this type. This is necessary for when nesting different StorageLayout's, so that the parent can
    /// calculate the slot for the child automatically (from its own slow).
    fn set_slot(&mut self, slot: BigInt);
}
impl_downcast!(StorageLayout);

pub trait ABIEncodeable {
    fn abi_token(&self) -> ethabi::Token;
    fn abi_decode(abi_encoded: &[u8]) -> Result<Self, ethabi::Error>
    where
        Self: Sized;
}

pub fn get_keccak_preimages_for_addresses(
    store: &impl HasAddresser,
    block: &pbeth::v2::Block,
) -> Vec<Vec<u8>> {
    let mut preimages: Vec<Vec<u8>> = vec![];
    for call in block.calls() {
        for change in &call.call.storage_changes {
            if store.has_address(Address::from_slice(change.address.as_slice())) {
                preimages.extend(
                    call.call
                        .keccak_preimages
                        .values()
                        .map(|preimage| -> Vec<u8> { substreams::Hex::decode(preimage).unwrap() }),
                );
                break;
            }
        }
    }
    preimages
}

/// Retrieves all storage changes in a block for all contracts under HasAddresser.
pub fn get_storage_changes_for_addresses(
    store: &impl HasAddresser,
    block: &pbeth::v2::Block,
) -> Vec<StorageChange> {
    let mut changes: Vec<StorageChange> = vec![];
    for call in block.calls() {
        for change in &call.call.storage_changes {
            if !store.has_address(Address::from_slice(change.address.as_slice())) {
                continue;
            }

            let mut preimage = None;
            let preimage_bytes = call
                .call
                .keccak_preimages
                .get(&substreams::Hex::encode(change.key.as_slice()));

            if let Some(unwrapped_preimage) = preimage_bytes {
                preimage = Some(substreams::Hex::decode(unwrapped_preimage).unwrap());
            }
            changes.push(StorageChange {
                change: change.to_owned(),
                preimage: preimage,
            });
        }
    }
    changes
}

pub fn keccak256(data: Vec<u8>) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    let mut output = [0u8; 32];
    keccak.update(data.as_slice());
    keccak.finalize(&mut output);
    output
}

/// Utility class to play around with Uint256 storage values.
pub struct Uint256 {
    pub slot: BigInt,
    pub value: BigInt,
}

impl Uint256 {
    pub fn storage_key(&self) -> Vec<u8> {
        ethabi::encode(&[self.slot.abi_token()])
    }
}

impl Default for Uint256 {
    fn default() -> Self {
        Uint256 {
            slot: BigInt::from(0),
            value: BigInt::from(0),
        }
    }
}

impl StorageLayout for Uint256 {
    fn size(&self) -> usize {
        SLOT_SIZE
    }

    fn decode(
        &mut self,
        slots: Vec<Vec<u8>>,
        _offset: Option<usize>,
    ) -> Result<(), StorageDecodingError> {
        if slots.len() != 1 {
            return Err(StorageDecodingError::new(format!(
                "Invalid number of slots for Uint256, expected 1, got {}",
                slots.len()
            )));
        }

        let decoded = match BigInt::abi_decode(slots[0].as_slice()) {
            Ok(decoded) => decoded,
            Err(err) => {
                return Err(StorageDecodingError::new(format!(
                    "Error decoding Uint256: {:?}",
                    err
                )))
            }
        };

        self.value = decoded;
        Ok(())
    }

    fn set_slot(&mut self, slot: BigInt) {
        self.slot = slot;
    }
}

/// Utility class to play around with Uint128 storage values.
pub struct Uint128 {
    pub slot: BigInt,
    pub value: BigInt,
    pub offset: usize,
}

impl Uint128 {
    pub fn storage_key(&self) -> Vec<u8> {
        ethabi::encode(&[self.slot.abi_token()])
    }
}

impl Default for Uint128 {
    fn default() -> Self {
        Uint128 {
            slot: BigInt::from(0),
            value: BigInt::from(0),
            offset: 0,
        }
    }
}

impl StorageLayout for Uint128 {
    fn size(&self) -> usize {
        16
    }

    fn decode(
        &mut self,
        slots: Vec<Vec<u8>>,
        offset: Option<usize>,
    ) -> Result<(), StorageDecodingError> {
        if slots.len() != 1 {
            return Err(StorageDecodingError::new(format!(
                "Invalid number of slots for Uint256, expected 1, got {}",
                slots.len()
            )));
        }

        if let Some(offset_override) = offset {
            self.offset = offset_override;
        }

        let raw = subslot(slots[0].clone(), self.size(), self.offset);
        let decoded = match BigInt::abi_decode(raw.as_slice()) {
            Ok(decoded) => decoded,
            Err(err) => {
                return Err(StorageDecodingError::new(format!(
                    "Error decoding Uint128: {:?}",
                    err
                )))
            }
        };

        self.value = decoded;
        Ok(())
    }

    fn set_slot(&mut self, slot: BigInt) {
        self.slot = slot;
    }
}

pub struct StructField {
    pub name: String,
    value: Box<dyn StorageLayout>,
    offset: usize,
    start_slot: usize,
    end_slot: usize,
}

pub struct EvmStruct {
    pub slot: BigInt,
    fields: Vec<StructField>,
    cumulative_size: usize,
    current_slot: usize,
}

impl EvmStruct {
    pub fn new(slot: BigInt) -> Self {
        EvmStruct {
            slot: slot,
            fields: vec![],
            cumulative_size: 0,
            current_slot: 0,
        }
    }

    pub fn add_field<T>(&mut self, name: &str, field: T)
    where
        T: StorageLayout + 'static,
    {
        let mut start_slot = self.cumulative_size / SLOT_SIZE;
        let mut field_offset = self.cumulative_size % SLOT_SIZE;
        if field_offset + field.size() > SLOT_SIZE {
            field_offset = 0;
            start_slot += 1;
            self.cumulative_size = start_slot * SLOT_SIZE;
        }

        let end_slot = start_slot + size_to_slots(field.size());
        self.current_slot = end_slot;
        self.cumulative_size += field.size();

        self.fields.push(StructField {
            name: name.to_string(),
            value: Box::new(field),
            offset: field_offset,
            start_slot: start_slot,
            end_slot: end_slot,
        });
    }

    pub fn get<T: StorageLayout>(&self, name: &str) -> &T {
        for field in &self.fields {
            if field.name == name {
                return field.value.downcast_ref::<T>().unwrap();
            }
        }
        panic!("Field {} not found", name);
    }
}

impl StorageLayout for EvmStruct {
    fn size(&self) -> usize {
        size_to_slots(self.cumulative_size) * SLOT_SIZE
    }

    fn decode(
        &mut self,
        slots: Vec<Vec<u8>>,
        _offset: Option<usize>,
    ) -> Result<(), StorageDecodingError> {
        if slots.len() < self.current_slot {
            return Err(StorageDecodingError::new(format!(
                "Invalid number of slots for EvmStruct, expected {}, got {}",
                size_to_slots(self.size()),
                slots.len()
            )));
        }

        let field_count = self.fields.len();
        for i in 0..field_count {
            let field = &mut self.fields[i];
            field.value.decode(
                slots[field.start_slot as usize..field.end_slot as usize].to_vec(),
                Some(field.offset),
            )?;
        }
        Ok(())
    }

    fn set_slot(&mut self, slot: BigInt) {
        self.slot = slot;
    }
}

pub struct Array<T: StorageLayout> {
    pub slot: BigInt,
    pub item: T,
}

impl<T: StorageLayout> Array<T> {
    pub fn new(slot: BigInt, item: T) -> Self {
        let mut arr = Array {
            slot: slot,
            item: item,
        };

        let item_slot = keccak256(arr.encoded_slot());
        arr.item.set_slot(BigInt::abi_decode(&item_slot).unwrap());
        arr
    }

    /// Will return a list of all storage changes involving this array, from a given list of changes.
    pub fn filter_array_changes(
        &self,
        changes: Vec<StorageChange>,
        expected_array_len: BigInt,
    ) -> Vec<StorageChange> {
        let mut filtered_changes = vec![];
        for change in changes {
            if let Some(index) = self.infer_array_index_from_storage_key(change.change.key.clone())
            {
                if index <= expected_array_len {
                    filtered_changes.push(change);
                }
            }
        }
        filtered_changes
    }

    pub fn infer_array_index_from_storage_key(&self, key: Vec<u8>) -> Option<BigInt> {
        let first_elem = self.storage_key_at_index(BigInt::zero());
        let target_val = BigInt::abi_decode(key.as_slice()).unwrap();
        let first_val = BigInt::abi_decode(&first_elem).unwrap();

        if target_val < first_val {
            return None;
        }

        let slot_diff = target_val - first_val;
        let slots_per_item = size_to_slots(self.item.size());
        if slot_diff.modulo(slots_per_item) != BigInt::zero() {
            return None;
        }

        Some(slot_diff / slots_per_item)
    }

    /// Returns the EVM storage key where the value of a given array index is stored.
    pub fn storage_key_at_index(&self, index: BigInt) -> Vec<u8> {
        let slots_per_item = BigInt::from(size_to_slots(self.item.size()));
        let output = keccak256(self.encoded_slot());
        let pos0 = BigInt::abi_decode(&output).unwrap();
        let pos_n = pos0 + index * slots_per_item;
        ethabi::encode(&[pos_n.abi_token()])
    }

    fn encoded_slot(&self) -> Vec<u8> {
        ethabi::encode(&[self.slot.abi_token()])
    }
}

impl<T: StorageLayout> StorageLayout for Array<T> {
    fn size(&self) -> usize {
        SLOT_SIZE
    }

    fn decode(
        &mut self,
        slots: Vec<Vec<u8>>,
        _offset: Option<usize>,
    ) -> Result<(), StorageDecodingError> {
        if slots.len() != size_to_slots(self.item.size()) {
            return Err(StorageDecodingError::new(format!(
                "Invalid number of slots for Array, expected {}, got {}",
                size_to_slots(self.item.size()),
                slots.len()
            )));
        }

        self.item.decode(slots, None)
    }

    fn set_slot(&mut self, slot: BigInt) {
        self.slot = slot;
    }
}

/// Utility class to play around with Mapping storage values.
pub struct Mapping {
    pub slot: BigInt,
}

impl Mapping {
    pub fn filter_keccak_preimages(&self, preimages: Vec<Vec<u8>>) -> Vec<KeccakPreimage> {
        let mut out = vec![];
        for preimage in preimages {
            if self.preimage_in_slot(preimage.clone()) {
                out.push(KeccakPreimage {
                    preimage: preimage.clone(),
                    slot: BigInt::abi_decode(keccak256(preimage).as_ref()).unwrap(),
                });
            }
        }
        out
    }

    /// For a given key, will calculate the abi encoded keccak preimage.
    /// Hashing the preimage will return the storage key where a given value from the mapping is.
    pub fn preimage(&self, key: &impl ABIEncodeable) -> Vec<u8> {
        ethabi::encode(&[key.abi_token(), self.slot.abi_token()])
    }

    /// Returns the EVM storage key where the given mapping key is stored.
    pub fn storage_key(&self, key: &impl ABIEncodeable) -> Vec<u8> {
        let preimage = self.preimage(key);
        return keccak256(preimage).to_vec();
    }

    /// Given a keccak256 preimage, determines what is the key of the mapping associated to it.
    /// Returns None if the format is wrong or there isn't a match.
    pub fn key_from_preimage<T: ABIEncodeable>(&self, preimage: Vec<u8>) -> Option<T> {
        if !self.preimage_in_slot(preimage.clone()) {
            return None;
        }

        let key = preimage
            .split_at(preimage.len() - &self.encoded_slot().len())
            .0;
        let t = T::abi_decode(key);
        if t.is_err() {
            return None;
        }
        Some(t.unwrap())
    }

    pub fn preimage_in_slot(&self, preimage: Vec<u8>) -> bool {
        preimage.ends_with(&self.encoded_slot().as_slice())
    }

    fn encoded_slot(&self) -> Vec<u8> {
        ethabi::encode(&[self.slot.abi_token()])
    }
}

impl ABIEncodeable for BigInt {
    fn abi_token(&self) -> ethabi::Token {
        ethabi::Token::Uint(ethabi::Uint::from_big_endian(
            self.to_bytes_be().1.as_slice(),
        ))
    }

    fn abi_decode(abi_encoded: &[u8]) -> Result<Self, ethabi::Error> {
        let mut bytes: [u8; SLOT_SIZE] = [0; SLOT_SIZE];
        let first = ethabi::Uint::from_big_endian(abi_encoded);
        first.to_big_endian(&mut bytes);
        Ok(BigInt::from_unsigned_bytes_be(&bytes))
    }
}

impl ABIEncodeable for Address {
    fn abi_token(&self) -> ethabi::Token {
        ethabi::Token::Address(self.clone())
    }

    fn abi_decode(abi_encoded: &[u8]) -> Result<Self, ethabi::Error> {
        let decoded = ethabi::decode(&[ethabi::ParamType::Address], abi_encoded)?;
        Ok(decoded[0].to_owned().into_address().unwrap())
    }
}

pub fn size_to_slots(size: usize) -> usize {
    if size % SLOT_SIZE == 0 {
        size / SLOT_SIZE
    } else {
        size / SLOT_SIZE + 1
    }
}

fn subslot(mut slot: Vec<u8>, size: usize, offset: usize) -> Vec<u8> {
    slot.reverse();

    let mut output = vec![0; size];
    output.copy_from_slice(&slot[offset..offset + size]);
    output.reverse();
    output
}
