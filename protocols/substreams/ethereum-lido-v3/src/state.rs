use anyhow::{anyhow, Result};
use serde::Deserialize;
use tycho_substreams::models::{Attribute, ChangeType};

use crate::{
    constants::{
        BUFFERED_ETHER_AND_DEPOSITED_VALIDATORS_ATTR, CL_BALANCE_AND_CL_VALIDATORS_ATTR,
        STAKING_STATE_ATTR, TOTAL_AND_EXTERNAL_SHARES_ATTR,
    },
    utils::{attribute_with_bytes, bytes_from_hex},
};

#[derive(Clone, Debug, Deserialize)]
pub struct InitialState {
    pub start_block: u64,
    pub total_and_external_shares: String,
    pub buffered_ether_and_deposited_validators: String,
    pub cl_balance_and_cl_validators: String,
    pub staking_state: String,
}

impl InitialState {
    pub fn parse(params: &str) -> Result<Self> {
        serde_json::from_str(params)
            .map_err(|e| anyhow!("Failed to parse Lido V3 initial state: {e}"))
    }

    pub fn steth_creation_attributes(&self) -> Result<Vec<Attribute>> {
        let mut attributes = self.shared_creation_attributes()?;
        attributes.push(attribute_with_bytes(
            STAKING_STATE_ATTR,
            &bytes_from_hex(&self.staking_state)?,
            ChangeType::Creation,
        ));
        Ok(attributes)
    }

    pub fn wsteth_creation_attributes(&self) -> Result<Vec<Attribute>> {
        self.shared_creation_attributes()
    }

    fn shared_creation_attributes(&self) -> Result<Vec<Attribute>> {
        Ok(vec![
            attribute_with_bytes(
                TOTAL_AND_EXTERNAL_SHARES_ATTR,
                &bytes_from_hex(&self.total_and_external_shares)?,
                ChangeType::Creation,
            ),
            attribute_with_bytes(
                BUFFERED_ETHER_AND_DEPOSITED_VALIDATORS_ATTR,
                &bytes_from_hex(&self.buffered_ether_and_deposited_validators)?,
                ChangeType::Creation,
            ),
            attribute_with_bytes(
                CL_BALANCE_AND_CL_VALIDATORS_ATTR,
                &bytes_from_hex(&self.cl_balance_and_cl_validators)?,
                ChangeType::Creation,
            ),
        ])
    }
}
