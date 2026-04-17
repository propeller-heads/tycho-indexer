use anyhow::{anyhow, Result};
use serde::Deserialize;
use substreams::scalar::BigInt;
use tycho_substreams::models::{Attribute, ChangeType};

use crate::{
    constants::{
        BUFFERED_ETHER_ATTR, CL_BALANCE_ATTR, CL_VALIDATORS_ATTR, DEPOSITED_VALIDATORS_ATTR,
        EXTERNAL_SHARES_ATTR, INTERNAL_ETHER_ATTR, INTERNAL_SHARES_ATTR, STAKING_STATE_ATTR,
        TOTAL_SHARES_ATTR,
    },
    utils::{attribute_with_bigint, bigint_from_hex},
};

#[derive(Clone, Debug, Default)]
pub struct LidoProtocolState {
    pub total_shares: BigInt,
    pub external_shares: BigInt,
    pub buffered_ether: BigInt,
    pub deposited_validators: BigInt,
    pub cl_balance: BigInt,
    pub cl_validators: BigInt,
    pub staking_state: BigInt,
}

impl LidoProtocolState {
    pub fn from_initial(initial_state: &InitialState) -> Result<Self> {
        Ok(Self {
            total_shares: bigint_from_hex(&initial_state.total_shares)?,
            external_shares: bigint_from_hex(&initial_state.external_shares)?,
            buffered_ether: bigint_from_hex(&initial_state.buffered_ether)?,
            deposited_validators: bigint_from_hex(&initial_state.deposited_validators)?,
            cl_balance: bigint_from_hex(&initial_state.cl_balance)?,
            cl_validators: bigint_from_hex(&initial_state.cl_validators)?,
            staking_state: bigint_from_hex(&initial_state.staking_state)?,
        })
    }

    pub fn apply_attribute(&mut self, name: &str, value: BigInt) -> Result<()> {
        match name {
            TOTAL_SHARES_ATTR => self.total_shares = value,
            EXTERNAL_SHARES_ATTR => self.external_shares = value,
            BUFFERED_ETHER_ATTR => self.buffered_ether = value,
            DEPOSITED_VALIDATORS_ATTR => self.deposited_validators = value,
            CL_BALANCE_ATTR => self.cl_balance = value,
            CL_VALIDATORS_ATTR => self.cl_validators = value,
            STAKING_STATE_ATTR => self.staking_state = value,
            _ => return Err(anyhow!("Unknown Lido V3 attribute: {name}")),
        }

        Ok(())
    }

    pub fn internal_ether(&self) -> BigInt {
        let deposit_size = num_bigint::BigInt::parse_bytes(b"32000000000000000000", 10)
            .expect("Failed to parse Lido deposit size");
        let transient_ether =
            (&self.deposited_validators - &self.cl_validators) * BigInt::from(deposit_size);
        &self.buffered_ether + &self.cl_balance + transient_ether
    }

    pub fn internal_shares(&self) -> BigInt {
        &self.total_shares - &self.external_shares
    }

    pub fn shared_creation_attributes(&self) -> Vec<Attribute> {
        self.shared_attributes(ChangeType::Creation)
    }

    pub fn shared_update_attributes(&self) -> Vec<Attribute> {
        self.shared_attributes(ChangeType::Update)
    }

    pub fn steth_creation_attributes(&self) -> Vec<Attribute> {
        let mut attributes = self.shared_creation_attributes();
        attributes.push(attribute_with_bigint(
            STAKING_STATE_ATTR,
            &self.staking_state,
            ChangeType::Creation,
        ));
        attributes
    }

    fn shared_attributes(&self, change: ChangeType) -> Vec<Attribute> {
        vec![
            attribute_with_bigint(TOTAL_SHARES_ATTR, &self.total_shares, change),
            attribute_with_bigint(EXTERNAL_SHARES_ATTR, &self.external_shares, change),
            attribute_with_bigint(BUFFERED_ETHER_ATTR, &self.buffered_ether, change),
            attribute_with_bigint(DEPOSITED_VALIDATORS_ATTR, &self.deposited_validators, change),
            attribute_with_bigint(CL_BALANCE_ATTR, &self.cl_balance, change),
            attribute_with_bigint(CL_VALIDATORS_ATTR, &self.cl_validators, change),
            attribute_with_bigint(INTERNAL_ETHER_ATTR, &self.internal_ether(), change),
            attribute_with_bigint(INTERNAL_SHARES_ATTR, &self.internal_shares(), change),
        ]
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct InitialState {
    pub start_block: u64,
    pub total_shares: String,
    pub external_shares: String,
    pub buffered_ether: String,
    pub deposited_validators: String,
    pub cl_balance: String,
    pub cl_validators: String,
    pub staking_state: String,
}

impl InitialState {
    pub fn parse(params: &str) -> Result<Self> {
        serde_json::from_str(params)
            .map_err(|e| anyhow!("Failed to parse Lido V3 initial state: {e}"))
    }
}
