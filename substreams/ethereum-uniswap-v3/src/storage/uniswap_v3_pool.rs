use crate::{
    pb::tycho::evm::v1::{Attribute, ChangeType},
    storage::utils,
};
use substreams::scalar::BigInt;
use substreams_ethereum::pb::eth::v2::StorageChange;

pub struct UniswapPoolStorage<'a> {
    pub storage_changes: &'a Vec<StorageChange>,
    pub contract_addr: [u8; 20],
}

impl<'a> UniswapPoolStorage<'a> {
    pub fn new(
        storage_changes: &'a Vec<StorageChange>,
        contract_addr: &[u8],
    ) -> UniswapPoolStorage<'a> {
        Self { storage_changes, contract_addr: utils::contract_pad(contract_addr) }
    }

    pub fn liquidity(&self) -> Option<(BigInt, BigInt)> {
        let liquidity_slot = BigInt::from(4);
        let offset = 0;
        let number_of_bytes = 16;

        // ----
        let slot_key = utils::left_pad_from_bigint(&liquidity_slot);
        // ----

        if let Some((old_data, new_data)) =
            utils::get_storage_change(&self.filtered_changes(), slot_key, offset, number_of_bytes)
        {
            Some((BigInt::from_signed_bytes_be(old_data), BigInt::from_signed_bytes_be(new_data)))
        } else {
            None
        }
    }

    pub fn protocol_fees(&self, token_0: bool) -> Option<(BigInt, BigInt)> {
        let liquidity_slot = BigInt::from(3);
        let offset = if token_0 { 0 } else { 16 };
        let number_of_bytes = 16;

        // ----
        let slot_key = utils::left_pad_from_bigint(&liquidity_slot);
        // ----

        if let Some((old_data, new_data)) =
            utils::get_storage_change(&self.filtered_changes(), slot_key, offset, number_of_bytes)
        {
            Some((BigInt::from_signed_bytes_be(old_data), BigInt::from_signed_bytes_be(new_data)))
        } else {
            None
        }
    }

    pub fn slot0(&self) -> Slot0Struct {
        let slot0_slot = utils::left_pad_from_bigint(&BigInt::from(0));
        return Slot0Struct::new(self.filtered_changes(), slot0_slot);
    }

    pub fn ticks(&self, tick_idx: &BigInt) -> TickStruct {
        let ticks_slot = utils::left_pad_from_bigint(&BigInt::from(5));
        let ticker_struct_slot =
            utils::calc_map_slot(&utils::left_pad_from_bigint(tick_idx), &ticks_slot);
        return TickStruct::new(self.filtered_changes(), ticker_struct_slot);
    }

    fn filtered_changes(&self) -> Vec<&StorageChange> {
        //TODO: not efficient
        return self
            .storage_changes
            .iter()
            .filter(|change| change.address == self.contract_addr)
            .collect();
    }

    pub fn get_changed_attributes(&self) -> Vec<Attribute> {
        //TODO: This is really not efficient, we should only go through storage updates once and
        // get everything we need
        let mut changed_attributes = Vec::new();

        if let Some(liq) = self.liquidity() {
            changed_attributes.push(Attribute {
                name: "liquidity".to_string(),
                value: liq.1.to_signed_bytes_le(),
                change: ChangeType::Update.into(),
            });
        }

        if let Some(price) = self.slot0().sqrt_price_x96() {
            changed_attributes.push(Attribute {
                name: "sqrt_price".to_string(),
                value: price.1.to_signed_bytes_le(),
                change: ChangeType::Update.into(),
            });
        }

        if let Some(tick) = self.slot0().tick() {
            changed_attributes.push(Attribute {
                name: "tick".to_string(),
                value: tick.1.to_signed_bytes_le(),
                change: ChangeType::Update.into(),
            });
        }

        if let Some(fee_protocol) = self.slot0().fee_protocol() {
            changed_attributes.push(Attribute {
                name: "fee_protocol".to_string(),
                value: fee_protocol.1.to_signed_bytes_le(),
                change: ChangeType::Update.into(),
            });
        }

        if let Some(fee) = self.protocol_fees(true) {
            changed_attributes.push(Attribute {
                name: "protocol_fees/token0".to_string(),
                value: fee.1.to_signed_bytes_le(),
                change: ChangeType::Update.into(),
            });
        }

        if let Some(fee) = self.protocol_fees(false) {
            changed_attributes.push(Attribute {
                name: "protocol_fees/token1".to_string(),
                value: fee.1.to_signed_bytes_le(),
                change: ChangeType::Update.into(),
            });
        }

        changed_attributes
    }
}

pub struct Slot0Struct<'a> {
    pub storage_changes: Vec<&'a StorageChange>,
    pub struct_slot: [u8; 32],
}

impl<'a> Slot0Struct<'a> {
    pub fn new(storage_changes: Vec<&'a StorageChange>, struct_slot: [u8; 32]) -> Slot0Struct<'a> {
        Self { struct_slot, storage_changes }
    }

    // the current price
    pub fn sqrt_price_x96(&self) -> Option<(BigInt, BigInt)> {
        let slot = BigInt::zero();
        let offset = 0;
        let number_of_bytes = 20;
        // &left_pad_from_bigint(&slot0_slot)

        let slot_key = utils::calc_struct_slot(&self.struct_slot, slot);

        if let Some((old_data, new_data)) =
            utils::get_storage_change(&self.storage_changes, slot_key, offset, number_of_bytes)
        {
            Some((BigInt::from_signed_bytes_be(old_data), BigInt::from_signed_bytes_be(new_data)))
        } else {
            None
        }
    }

    // the current tick
    pub fn tick(&self) -> Option<(BigInt, BigInt)> {
        let slot = BigInt::zero();
        let offset = 20;
        let number_of_bytes = 3;
        // &left_pad_from_bigint(&slot0_slot)

        let slot_key = utils::calc_struct_slot(&self.struct_slot, slot);

        if let Some((old_data, new_data)) =
            utils::get_storage_change(&self.storage_changes, slot_key, offset, number_of_bytes)
        {
            Some((BigInt::from_signed_bytes_be(old_data), BigInt::from_signed_bytes_be(new_data)))
        } else {
            None
        }
    }

    // the current protocol fee as a percentage of the swap fee taken on withdrawal
    // represented as an integer denominator (1/x)%
    pub fn fee_protocol(&self) -> Option<(BigInt, BigInt)> {
        let slot = BigInt::zero();
        let offset = 29;
        let number_of_bytes = 1;

        let slot_key = utils::calc_struct_slot(&self.struct_slot, slot);

        if let Some((old_data, new_data)) =
            utils::get_storage_change(&self.storage_changes, slot_key, offset, number_of_bytes)
        {
            Some((BigInt::from_signed_bytes_be(old_data), BigInt::from_signed_bytes_be(new_data)))
        } else {
            None
        }
    }
}

pub struct TickStruct<'a> {
    pub storage_changes: Vec<&'a StorageChange>,
    pub struct_slot: [u8; 32],
}

impl<'a> TickStruct<'a> {
    pub fn new(storage_changes: Vec<&'a StorageChange>, struct_slot: [u8; 32]) -> TickStruct<'a> {
        Self { struct_slot, storage_changes }
    }

    pub fn net_liquidity(&self) -> Option<(BigInt, BigInt)> {
        let slot = BigInt::from(0);
        let offset = 16;
        let number_of_bytes = 16;

        let slot_key = utils::calc_struct_slot(&self.struct_slot, slot);

        if let Some((old_data, new_data)) =
            utils::get_storage_change(&self.storage_changes, slot_key, offset, number_of_bytes)
        {
            Some((BigInt::from_signed_bytes_be(old_data), BigInt::from_signed_bytes_be(new_data)))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::storage::{uniswap_v3_pool::UniswapPoolStorage, utils};
    use std::{fmt::Write, str::FromStr};
    use substreams::{hex, scalar::BigInt};
    use substreams_ethereum::pb::eth::v2::StorageChange;

    #[test]
    fn slot0_sqrt_price_x96() {
        // derived from: https://etherscan.io/tx/0x37d8f4b1b371fde9e4b1942588d16a1cbf424b7c66e731ec915aca785ca2efcf#statechange
        let storage_changes = vec![StorageChange {
            address: hex!("7858e59e0c01ea06df3af3d20ac7b0003275d4bf").to_vec(),
            key: hex!("0000000000000000000000000000000000000000000000000000000000000000").to_vec(),
            old_value: hex!("0000000000000000000000000000000000000000000000000000000000000000")
                .to_vec(),
            new_value: hex!("000100000100010000ff556d00000000000000001cd851cd075726f0cf78926d")
                .to_vec(),
            ordinal: 0,
        }];

        let storage = UniswapPoolStorage::new(
            &storage_changes,
            hex!("7858e59e0c01ea06df3af3d20ac7b0003275d4bf").as_ref(),
        );
        let v_opt = storage.slot0().sqrt_price_x96();
        assert_eq!(
            Some((
                BigInt::from_str("0").unwrap(),
                BigInt::from_str("8927094545831003674704908909").unwrap()
            )),
            v_opt
        );
    }

    #[test]
    fn slot0_tick() {
        // derived from: https://etherscan.io/tx/0x37d8f4b1b371fde9e4b1942588d16a1cbf424b7c66e731ec915aca785ca2efcf#statechange
        let storage_changes = vec![StorageChange {
            address: hex!("7858e59e0c01ea06df3af3d20ac7b0003275d4bf").to_vec(),
            key: hex!("0000000000000000000000000000000000000000000000000000000000000000").to_vec(),
            old_value: hex!("0000000000000000000000000000000000000000000000000000000000000000")
                .to_vec(),
            new_value: hex!("000100000100010000ff556d00000000000000001cd851cd075726f0cf78926d")
                .to_vec(),
            ordinal: 0,
        }];

        let storage = UniswapPoolStorage::new(
            &storage_changes,
            hex!("7858e59e0c01ea06df3af3d20ac7b0003275d4bf").as_ref(),
        );
        let v_opt = storage.slot0().tick();
        assert_eq!(
            Some((BigInt::from_str("0").unwrap(), BigInt::from_str("-43667").unwrap())),
            v_opt
        );
    }

    #[test]
    fn slot0_fee_protocol() {
        // derived from: https://etherscan.io/tx/0x37d8f4b1b371fde9e4b1942588d16a1cbf424b7c66e731ec915aca785ca2efcf#statechange
        let storage_changes = vec![StorageChange {
            address: hex!("7858e59e0c01ea06df3af3d20ac7b0003275d4bf").to_vec(),
            key: hex!("0000000000000000000000000000000000000000000000000000000000000000").to_vec(),
            old_value: hex!("0000000000000000000000000000000000000000000000000000000000000000")
                .to_vec(),
            new_value: hex!("000100000100010000ff556d00000000000000001cd851cd075726f0cf78926d")
                .to_vec(),
            ordinal: 0,
        }];

        let storage = UniswapPoolStorage::new(
            &storage_changes,
            hex!("7858e59e0c01ea06df3af3d20ac7b0003275d4bf").as_ref(),
        );
        let v_opt = storage.slot0().fee_protocol();
        // going from 0 to 0 yields no change
        assert_eq!(None, v_opt);
    }

    #[test]
    fn liquidity() {
        let storage_changes = vec![
            StorageChange {
                address: hex!("779dfffb81550bf503c19d52b1e91e9251234faa").to_vec(),
                key: hex!("8c69d40e3965e41bbc8bb190dc6bbd6d8ed6cfc434af11479a9d93bd6d8d7b04")
                    .to_vec(),
                old_value: hex!("0100000000000000000000000000000000000000000000000000000000000000")
                    .to_vec(),
                new_value: hex!("0161f0d813000000000000000000202dca4db2607b4eeb0089ffff82608219c4")
                    .to_vec(),
                ordinal: 152,
            },
            StorageChange {
                address: hex!("779dfffb81550bf503c19d52b1e91e9251234faa").to_vec(),
                key: hex!("62ea84ea9c7793817b7c95726c87fd532ffdc92644a26b6448fe793434ef1c04")
                    .to_vec(),
                old_value: hex!("0000000000000000000000000000000000000000000000000000000000000000")
                    .to_vec(),
                new_value: hex!("00000000000000000000000000000000005955c9750c2d183783fb18efd9ed86")
                    .to_vec(),
                ordinal: 160,
            },
            StorageChange {
                address: hex!("779dfffb81550bf503c19d52b1e91e9251234faa").to_vec(),
                key: hex!("0000000000000000000000000000000000000000000000000000000000000004")
                    .to_vec(),
                old_value: hex!("000000000000000000000000000000000000000000000051eb0c7b51a54cf028")
                    .to_vec(),
                new_value: hex!("0000000000000000000000000000000000000000000000000000000000000000")
                    .to_vec(),
                ordinal: 287,
            },
        ];

        let storage = UniswapPoolStorage::new(
            &storage_changes,
            hex!("779dfffb81550bf503c19d52b1e91e9251234faa").as_ref(),
        );

        let v_opt = storage.liquidity();
        assert_eq!(
            Some((BigInt::from_str("1511123317859703124008").unwrap(), BigInt::from(0))),
            v_opt
        );
    }

    #[test]
    fn slot_calc() {
        // slot of ticks map
        let ticks_slot = BigInt::from(5);
        // tick index in map we are looking for
        let tick_idx = BigInt::from(193200);

        let ticks_slot = utils::left_pad_from_bigint(&ticks_slot);
        let ticker_struct_slot =
            utils::calc_map_slot(&utils::left_pad_from_bigint(&tick_idx), &ticks_slot);

        // slot of the initialized attribute within the tick struct
        let struct_attr_slot = BigInt::from(3);

        let slot_key = utils::calc_struct_slot(&ticker_struct_slot, struct_attr_slot);
        assert_eq!(
            "59d3454e6bb14d1f2ae9ab5d64a71e9d2d3eec41710c33f701d47eb206f29613",
            encode_hex(ticker_struct_slot.as_slice())
        );
        assert_eq!(
            "59d3454e6bb14d1f2ae9ab5d64a71e9d2d3eec41710c33f701d47eb206f29616",
            encode_hex(slot_key.as_slice())
        );
    }

    fn encode_hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            write!(&mut s, "{:02x}", b).unwrap();
        }
        s
    }
}
