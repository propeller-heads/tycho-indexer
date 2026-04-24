use crate::log::Log;
use crate::model::Vault;
use crate::params::Params;
use crate::{Address, State};
use serde::Serialize;
use serde::ser::SerializeMap;

/// Combines all elements of a successful [Result] of [simulate](crate::simulate::simulate):
/// The input [Params] and the output [State], [Vault] and [Log].
/// Serialized into the YAML that's written to stdout for every suspicious state.
pub struct Outcome<T> {
    params: Params,
    state: State,
    vault: Vault,
    log: T,
}

impl<T: Log> Outcome<T> {
    pub fn new(params: Params, mut state: State, mut vault: Vault, log: T) -> Self {
        // in order to keep the serialized output readable and compact
        // remove zero valued entries in various maps
        state.owner_to_eth_balance.retain(|_, v| *v != 0);
        state.owner_and_token_to_balance.retain(|_, v| *v != 0);
        state
            .token_and_owner_and_spender_to_allowance
            .retain(|_, v| *v != 0);
        vault.owner_and_token_to_balance.retain(|_, v| *v != 0);
        vault.deltas.retain(|_, v| *v != 0);

        Self {
            params,
            state,
            vault,
            log,
        }
    }

    /// Right now the [Outcome] is considered suspicious if the
    /// caller ends up with more ETH or WETH on the addresses they
    /// control ([Address::is_sender_controlled]) than they had before
    /// the transaction.
    ///
    /// TODO should be extended to detect more suspicious scenarios.
    /// only looks at situations where the user can steal assets.
    /// TODO also detect situations where the user can waste assets.
    pub fn is_suspicious(&self) -> bool {
        let msg_value: i64 = self.params.get("msg_value").unwrap_or(0);
        self.final_caller_eth_balance() > msg_value
    }

    /// Return the positive or negative ETH and WETH balance the caller
    /// has at the end of the simulated transaction
    /// accross all addresses they control ([Address::is_sender_controlled]).
    pub fn final_caller_eth_balance(&self) -> i64 {
        let mut total_eth = 0;
        for (owner, balance) in &self.state.owner_to_eth_balance {
            if owner.is_sender_controlled() {
                total_eth += balance;
            }
        }
        for ((owner, token), balance) in &self.state.owner_and_token_to_balance {
            if owner.is_sender_controlled() {
                // TODO if you introduce other value holding erc20 tokens,
                // make sure to add code for them here and introduce
                // some fixed conversion rate to eth
                if *token == Address::WETH {
                    total_eth += balance;
                }
            }
        }
        for ((token, _, spender), router_allowance) in
            &self.state.token_and_owner_and_spender_to_allowance
        {
            if spender.is_sender_controlled() {
                // TODO if you introduce other value holding erc20 tokens,
                // make sure to add code for them here and introduce
                // some fixed conversion rate to eth
                if *token == Address::WETH {
                    total_eth += router_allowance;
                }
            }
        }
        for ((owner, token), balance) in &self.vault.owner_and_token_to_balance {
            if owner.is_sender_controlled() {
                // TODO if you introduce other value holding erc20 tokens,
                // make sure to add code for them here and introduce
                // some fixed conversion rate to eth
                if *token == Address::Zero || *token == Address::WETH {
                    total_eth += balance;
                }
            }
        }
        total_eth
    }
}

/// [Outcome]'s serialization is so customized that it leads to
/// much simpler code implementing it from scratch instead of
/// using serde's configuration attributes.
impl<T: Log + Serialize> Serialize for Outcome<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut s = serializer.serialize_map(None)?;
        s.serialize_entry("params", &self.params)?;
        let final_caller_eth_balance = self.final_caller_eth_balance();
        if final_caller_eth_balance > 0 {
            s.serialize_entry("final_caller_eth_balance", &final_caller_eth_balance)?;
        }

        if !self.state.owner_to_eth_balance.is_empty() {
            s.serialize_entry("eth_balance", &self.state.owner_to_eth_balance)?;
        }

        if !self.state.owner_and_token_to_balance.is_empty() {
            s.serialize_entry("erc20_balance", &self.state.owner_and_token_to_balance)?;
        }

        if !self
            .state
            .token_and_owner_and_spender_to_allowance
            .is_empty()
        {
            s.serialize_entry(
                "erc20_allowance",
                &self.state.token_and_owner_and_spender_to_allowance,
            )?;
        }

        if !self.vault.owner_and_token_to_balance.is_empty() {
            s.serialize_entry("vault_balance", &self.vault.owner_and_token_to_balance)?;
        }

        if self.vault._get_nonzero_delta_count() > 0 {
            s.serialize_entry(
                "nonzero_delta_count",
                &self.vault._get_nonzero_delta_count(),
            )?;
        }

        if !self.vault.deltas.is_empty() {
            s.serialize_entry("vault_delta", &self.vault.deltas)?;
        }

        if !self.log.is_empty() {
            s.serialize_entry("log", &self.log)?;
        }
        s.end()
    }
}
