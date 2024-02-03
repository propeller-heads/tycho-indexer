use crate::{
    pb::tycho::evm::v1::{Attribute, ChangeType},
    storage::utils,
};

use substreams::scalar::BigInt;
use substreams_ethereum::pb::eth::v2::StorageChange;

use super::{constants::TICKS_MAP_SLOT, utils::read_bytes};

#[derive(Clone)]
pub struct StorageLocation<'a> {
    pub name: &'a str,
    pub slot: [u8; 32],
    pub offset: usize,
    pub number_of_bytes: usize,
}

pub struct UniswapPoolStorage<'a> {
    pub storage_changes: &'a Vec<StorageChange>,
}

impl<'a> UniswapPoolStorage<'a> {
    pub fn new(storage_changes: &'a Vec<StorageChange>) -> UniswapPoolStorage<'a> {
        Self { storage_changes }
    }

    /// Iterates through storage changes and checks for modifications in the provided list of
    /// storage locations. For each change, it compares the old and new values at the specified
    /// offset and length for that location. If a change is detected, it's added to the returned
    /// `Attribute` list.
    ///
    /// Arguments:
    ///     locations: Vec<&StorageLocation> - A vector of references to StorageLocation objects
    /// that define the slots, offsets, and lengths to be checked for changes.
    ///
    /// Returns:
    ///     `Vec<Attribute>`: A vector containing Attributes for each change detected in the tracked
    /// slots. Returns an empty vector if no changes are detected.
    pub fn get_changed_attributes(&self, locations: Vec<&StorageLocation>) -> Vec<Attribute> {
        let mut attributes = Vec::new();

        // For each storage change, check if it changes a tracked slot.
        // If it does, add the attribute to the list of attributes
        for change in self.storage_changes {
            for storage_location in locations.iter() {
                // Check if the change slot matches the tracked slot
                if change.key == storage_location.slot {
                    let old_data = read_bytes(
                        &change.old_value,
                        storage_location.offset,
                        storage_location.number_of_bytes,
                    );
                    let new_data = read_bytes(
                        &change.new_value,
                        storage_location.offset,
                        storage_location.number_of_bytes,
                    );

                    // Check if there is a change in the data
                    if old_data != new_data {
                        attributes.push(Attribute {
                            name: storage_location.name.to_string(),
                            value: BigInt::from_signed_bytes_be(new_data).to_signed_bytes_le(),
                            change: ChangeType::Update.into(),
                        });
                    }
                }
            }
        }

        attributes
    }

    pub fn get_ticks_changes(&self, ticks_idx: Vec<&BigInt>) -> Vec<Attribute> {
        let mut locations = Vec::new();
        let mut tick_names = Vec::new();

        // First, create all the names and push them into tick_names.
        // We need this to keep the references to the names alive until we call
        // `get_changed_attributes()`
        for tick_idx in ticks_idx.iter() {
            tick_names.push(format!("ticks/{}/net-liquidity", tick_idx));
        }

        // Then, iterate over ticks_idx and tick_names simultaneously
        for (tick_idx, tick_name) in ticks_idx.iter().zip(tick_names.iter()) {
            let tick_slot =
                utils::calc_map_slot(&utils::left_pad_from_bigint(tick_idx), &TICKS_MAP_SLOT);

            locations.push(StorageLocation {
                name: tick_name,
                slot: tick_slot,
                offset: 16,
                number_of_bytes: 16,
            });
        }

        self.get_changed_attributes(locations.iter().collect())
    }
}

// #[cfg(test)]
// mod tests {
//     use crate::storage::{uniswap_v3_pool::UniswapPoolStorage, utils};
//     use std::{fmt::Write, str::FromStr};
//     use substreams::{hex, scalar::BigInt};
//     use substreams_ethereum::pb::eth::v2::StorageChange;

//     #[test]
//     fn test_get_changed_attributes() {
//         // derived from: https://etherscan.io/tx/0x37d8f4b1b371fde9e4b1942588d16a1cbf424b7c66e731ec915aca785ca2efcf#statechange
//         let storage_changes = vec![StorageChange {
//             address: hex!("7858e59e0c01ea06df3af3d20ac7b0003275d4bf").to_vec(),
//             key:
// hex!("0000000000000000000000000000000000000000000000000000000000000000").to_vec(),
// old_value: hex!("0000000000000000000000000000000000000000000000000000000000000000")
// .to_vec(),             new_value:
// hex!("000100000100010000ff556d00000000000000001cd851cd075726f0cf78926d")
// .to_vec(),             ordinal: 0,
//         }];

//         let storage = UniswapPoolStorage::new(
//             &storage_changes,
//             hex!("7858e59e0c01ea06df3af3d20ac7b0003275d4bf").as_ref(),
//         );
//         let v_opt = storage.slot0().sqrt_price_x96();
//         assert_eq!(
//             Some((
//                 BigInt::from_str("0").unwrap(),
//                 BigInt::from_str("8927094545831003674704908909").unwrap()
//             )),
//             v_opt
//         );
//     }

//     #[test]
//     fn slot0_tick() {
//         // derived from: https://etherscan.io/tx/0x37d8f4b1b371fde9e4b1942588d16a1cbf424b7c66e731ec915aca785ca2efcf#statechange
//         let storage_changes = vec![StorageChange {
//             address: hex!("7858e59e0c01ea06df3af3d20ac7b0003275d4bf").to_vec(),
//             key:
// hex!("0000000000000000000000000000000000000000000000000000000000000000").to_vec(),
// old_value: hex!("0000000000000000000000000000000000000000000000000000000000000000")
// .to_vec(),             new_value:
// hex!("000100000100010000ff556d00000000000000001cd851cd075726f0cf78926d")
// .to_vec(),             ordinal: 0,
//         }];

//         let storage = UniswapPoolStorage::new(
//             &storage_changes,
//             hex!("7858e59e0c01ea06df3af3d20ac7b0003275d4bf").as_ref(),
//         );
//         let v_opt = storage.slot0().tick();
//         assert_eq!(
//             Some((BigInt::from_str("0").unwrap(), BigInt::from_str("-43667").unwrap())),
//             v_opt
//         );
//     }

//     #[test]
//     fn slot0_fee_protocol() {
//         // derived from: https://etherscan.io/tx/0x37d8f4b1b371fde9e4b1942588d16a1cbf424b7c66e731ec915aca785ca2efcf#statechange
//         let storage_changes = vec![StorageChange {
//             address: hex!("7858e59e0c01ea06df3af3d20ac7b0003275d4bf").to_vec(),
//             key:
// hex!("0000000000000000000000000000000000000000000000000000000000000000").to_vec(),
// old_value: hex!("0000000000000000000000000000000000000000000000000000000000000000")
// .to_vec(),             new_value:
// hex!("000100000100010000ff556d00000000000000001cd851cd075726f0cf78926d")
// .to_vec(),             ordinal: 0,
//         }];

//         let storage = UniswapPoolStorage::new(
//             &storage_changes,
//             hex!("7858e59e0c01ea06df3af3d20ac7b0003275d4bf").as_ref(),
//         );
//         let v_opt = storage.slot0().fee_protocol();
//         // going from 0 to 0 yields no change
//         assert_eq!(None, v_opt);
//     }

//     #[test]
//     fn liquidity() {
//         let storage_changes = vec![
//             StorageChange {
//                 address: hex!("779dfffb81550bf503c19d52b1e91e9251234faa").to_vec(),
//                 key: hex!("8c69d40e3965e41bbc8bb190dc6bbd6d8ed6cfc434af11479a9d93bd6d8d7b04")
//                     .to_vec(),
//                 old_value:
// hex!("0100000000000000000000000000000000000000000000000000000000000000")
// .to_vec(),                 new_value:
// hex!("0161f0d813000000000000000000202dca4db2607b4eeb0089ffff82608219c4")
// .to_vec(),                 ordinal: 152,
//             },
//             StorageChange {
//                 address: hex!("779dfffb81550bf503c19d52b1e91e9251234faa").to_vec(),
//                 key: hex!("62ea84ea9c7793817b7c95726c87fd532ffdc92644a26b6448fe793434ef1c04")
//                     .to_vec(),
//                 old_value:
// hex!("0000000000000000000000000000000000000000000000000000000000000000")
// .to_vec(),                 new_value:
// hex!("00000000000000000000000000000000005955c9750c2d183783fb18efd9ed86")
// .to_vec(),                 ordinal: 160,
//             },
//             StorageChange {
//                 address: hex!("779dfffb81550bf503c19d52b1e91e9251234faa").to_vec(),
//                 key: hex!("0000000000000000000000000000000000000000000000000000000000000004")
//                     .to_vec(),
//                 old_value:
// hex!("000000000000000000000000000000000000000000000051eb0c7b51a54cf028")
// .to_vec(),                 new_value:
// hex!("0000000000000000000000000000000000000000000000000000000000000000")
// .to_vec(),                 ordinal: 287,
//             },
//         ];

//         let storage = UniswapPoolStorage::new(
//             &storage_changes,
//             hex!("779dfffb81550bf503c19d52b1e91e9251234faa").as_ref(),
//         );

//         let v_opt = storage.liquidity();
//         assert_eq!(
//             Some((BigInt::from_str("1511123317859703124008").unwrap(), BigInt::from(0))),
//             v_opt
//         );
//     }

//     #[test]
//     fn slot_calc() {
//         // slot of ticks map
//         let ticks_slot = BigInt::from(5);
//         // tick index in map we are looking for
//         let tick_idx = BigInt::from(193200);

//         let ticks_slot = utils::left_pad_from_bigint(&ticks_slot);
//         let ticker_struct_slot =
//             utils::calc_map_slot(&utils::left_pad_from_bigint(&tick_idx), &ticks_slot);

//         // slot of the initialized attribute within the tick struct
//         let struct_attr_slot = BigInt::from(3);

//         let slot_key = utils::calc_struct_slot(&ticker_struct_slot, struct_attr_slot);
//         assert_eq!(
//             "59d3454e6bb14d1f2ae9ab5d64a71e9d2d3eec41710c33f701d47eb206f29613",
//             encode_hex(ticker_struct_slot.as_slice())
//         );
//         assert_eq!(
//             "59d3454e6bb14d1f2ae9ab5d64a71e9d2d3eec41710c33f701d47eb206f29616",
//             encode_hex(slot_key.as_slice())
//         );
//     }

//     fn encode_hex(bytes: &[u8]) -> String {
//         let mut s = String::with_capacity(bytes.len() * 2);
//         for &b in bytes {
//             write!(&mut s, "{:02x}", b).unwrap();
//         }
//         s
//     }
// }
