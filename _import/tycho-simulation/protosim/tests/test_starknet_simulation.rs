#[cfg(test)]
mod tests {
    use cairo_vm::felt::Felt252;
    use dotenv::dotenv;
    use protosim::starknet_simulation::{
        rpc_reader::RpcStateReader,
        simulation::{ContractOverride, SimulationEngine, SimulationParameters},
    };
    use rpc_state_reader::rpc_state::{RpcChain, RpcState};
    use starknet_api::block::BlockNumber;
    use starknet_in_rust::utils::{felt_to_hash, get_storage_var_address, Address, ClassHash};
    use std::{collections::HashMap, env, sync::Arc};

    pub fn felt_str(val: &str) -> Felt252 {
        let base = if val.starts_with("0x") { 16_u32 } else { 10_u32 };
        let stripped_val = val.strip_prefix("0x").unwrap_or(val);

        Felt252::parse_bytes(stripped_val.as_bytes(), base).expect("Failed to parse input")
    }

    pub fn address_str(val: &str) -> Address {
        Address(felt_str(val))
    }

    fn setup_reader(block_number: u64) -> RpcStateReader {
        let infura_api_key = env::var("INFURA_API_KEY").unwrap_or_else(|_| {
            dotenv().expect("Missing .env file");
            env::var("INFURA_API_KEY").expect("Missing INFURA_API_KEY in .env file")
        });
        let rpc_endpoint = format!("https://{}.infura.io/v3/{}", RpcChain::MainNet, infura_api_key);
        let feeder_url = format!("https://{}.starknet.io/feeder_gateway", RpcChain::MainNet);
        RpcStateReader::new(RpcState::new(
            RpcChain::MainNet,
            BlockNumber(block_number).into(),
            &rpc_endpoint,
            &feeder_url,
        ))
    }

    fn setup_engine(
        block_number: u64,
        contract_overrides: Option<Vec<ContractOverride>>,
    ) -> SimulationEngine<RpcStateReader> {
        let rpc_state_reader = Arc::new(setup_reader(block_number));
        let contract_overrides = contract_overrides.unwrap_or_else(Vec::new);

        SimulationEngine::new(rpc_state_reader, contract_overrides).unwrap()
    }

    fn construct_token_overrides(
        wallet: Address,
        sell_token: Address,
        sell_amount: Felt252,
        spender: Address,
    ) -> Vec<ContractOverride> {
        // ERC20 contract overrides - using USDC token contract template
        let class_hash: ClassHash =
            hex::decode("052c7ba99c77fc38dd3346beea6c0753c3471f2e3135af5bb837d6c9523fff62")
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap();

        let mut storage_overrides = HashMap::new();

        // override balance
        let balance_storage_hash =
            felt_to_hash(&get_storage_var_address("ERC20_balances", &[wallet.0.clone()]).unwrap());
        storage_overrides.insert((sell_token.clone(), balance_storage_hash), sell_amount.clone());

        // override allowance
        let allowance_storage_hash = felt_to_hash(
            &get_storage_var_address("ERC20_allowances", &[wallet.0, spender.0]).unwrap(),
        );
        storage_overrides.insert((sell_token.clone(), allowance_storage_hash), sell_amount);

        let token_contract =
            ContractOverride::new(sell_token, class_hash, None, Some(storage_overrides));

        vec![token_contract]
    }

    #[test]
    #[cfg_attr(not(feature = "network_tests"), ignore)]
    fn test_consecutive_simulations_ekubo() {
        // Test vars
        let block_number = 354168;
        let token0 =
            address_str("0xda114221cb83fa859dbdb4c44beeaa0bb37c7537ad5ae66fe5e0efd20e6eb3");
        let token1 =
            address_str("0x068f5c6a61780768455de69077e07e89787839bf8166decfbf92b645209c0fb8");
        let test_wallet =
            address_str("0x065c19e14e2587d2de74c561b2113446ca4b389aabe6da1dc4accb6404599e99");
        let ekubo_address =
            address_str("0x00000005dd3d2f4429af886cd1a3b08289dbcea99a294197e9eb43b0e0325b4b");
        let sell_amount = felt_str("0x3bf9da25c1bfd31da");

        // Contruct engine with sell token override
        let contract_overrides = construct_token_overrides(
            test_wallet.clone(),
            token0.clone(),
            sell_amount.clone(),
            ekubo_address.clone(),
        );
        let mut engine = setup_engine(block_number, Some(contract_overrides));

        // obtained from this Ekubo core swap call: https://voyager.online/tx/0x634fa25f6b3fb6aceffbf689edb04eb24d4eb118a955d3439382a231e78b7e7#internalCalls
        let swap_calldata = vec![
            // Pool key data
            token0.0,                                    // token0
            token1.0,                                    // token1
            felt_str("0x5e59d28446cbf2061e33040400000"), // fee
            Felt252::from(10),                           // tick spacing
            Felt252::from(0),                            // extension
            // Swap data
            sell_amount,                                // amount
            Felt252::from(0),                           // amount sign
            Felt252::from(0),                           // istoken1
            felt_str("0x10c6cdcb20b7a5db24ca0ceb6980"), // sqrt ratio limit (lower bits
            Felt252::from(0),                           // sqrt ratio limit (upper bits)
            Felt252::from(100),                         // skip ahead
        ];

        let params = SimulationParameters::new(
            test_wallet,
            ekubo_address,
            swap_calldata,
            "swap".to_owned(),
            None,
            Some(100000),
            block_number,
        );

        let result0 = engine.simulate(&params);

        assert!(result0.is_ok())
    }
}
