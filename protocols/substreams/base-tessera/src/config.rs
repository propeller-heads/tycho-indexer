use serde::Deserialize;

/// Deployment-specific addresses and storage layout for a Tessera venue.
///
/// Supplied through substreams `params` (see `base-tessera.yaml`) so the module can be
/// re-pointed at another deployment (e.g. BSC) or a pair-implementation generation with a
/// different storage layout without code changes. Addresses are hex, no `0x` prefix.
///
/// Every address here is stable for the life of the deployment. The contracts a pair
/// delegatecalls into (its implementation, pricing lib and write-path contract) rotate roughly
/// monthly and are deliberately absent: their addresses are read from the pair's own storage
/// slots and published as `stateless_contract_addr_{i}` attributes, so consumers fetch their
/// code themselves and no params change is ever needed for an upgrade.
#[derive(Clone, Deserialize)]
pub struct DeploymentConfig {
    /// `TesseraSwap` — the verified swap/quote entrypoint.
    #[serde(with = "hex::serde")]
    pub tesseraswap: Vec<u8>,
    /// Pricing engine (TesseraSwap `slot0`); owns the pair registry.
    #[serde(with = "hex::serde")]
    pub engine: Vec<u8>,
    /// TesseraSwap storage slot holding the treasury (inventory custodian).
    pub treasury_slot: u64,
    /// Fallback treasury for runs whose initial block is patched past the constructor write
    /// (the protocol-testing harness does this). A production sync from the package's real
    /// initial block witnesses every treasury write, so this value is never read there.
    #[serde(with = "hex::serde")]
    pub treasury: Vec<u8>,
    /// Base slot of the engine's `pairKey => pair address` mapping. The pair key is
    /// `keccak256(abi.encode(tokenLo, tokenHi))` over the pair's two tokens sorted ascending,
    /// so the entry lives at `keccak256(abi.encode(pairKey, pair_map_slot))`.
    pub pair_map_slot: u64,
    /// Pair-contract slot holding the base token.
    pub pair_base_token_slot: u64,
    /// Pair-contract slot holding the packed `decimals ‖ quote token`.
    pub pair_quote_token_slot: u64,
    /// Pair-contract slot holding the pricing-lib address (assigned after creation, reassigned
    /// on lib upgrades). Published as `stateless_contract_addr_1`.
    pub pair_lib_slot: u64,
    /// Pair-contract slot holding the write-path contract address (assigned after creation).
    /// Published as `stateless_contract_addr_2`.
    pub pair_write_path_slot: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARAMS: &str = "tesseraswap=55555522005bcae1c2424d474bfd5ed477749e3e\
                          &engine=31e99e05fee3dce580af777c3fd63ee1b3b40c17\
                          &treasury_slot=1\
                          &treasury=3dbe077e7986657e95e1cc50089f17a5a4af0aae\
                          &pair_map_slot=8\
                          &pair_base_token_slot=48\
                          &pair_quote_token_slot=49\
                          &pair_lib_slot=51\
                          &pair_write_path_slot=52";

    #[test]
    fn parses_params() {
        let config: DeploymentConfig = serde_qs::from_str(PARAMS).unwrap();
        assert_eq!(config.tesseraswap.len(), 20);
        assert_eq!(config.engine.len(), 20);
        assert_eq!(hex::encode(&config.treasury), "3dbe077e7986657e95e1cc50089f17a5a4af0aae");
        assert_eq!(config.treasury_slot, 1);
        assert_eq!(config.pair_map_slot, 8);
        assert_eq!(config.pair_base_token_slot, 48);
        assert_eq!(config.pair_quote_token_slot, 49);
        assert_eq!(config.pair_lib_slot, 51);
        assert_eq!(config.pair_write_path_slot, 52);
    }

    #[test]
    fn rejects_params_without_the_write_path_slot() {
        let params = PARAMS.replace("&pair_write_path_slot=52", "");
        assert!(serde_qs::from_str::<DeploymentConfig>(&params).is_err());
    }
}
