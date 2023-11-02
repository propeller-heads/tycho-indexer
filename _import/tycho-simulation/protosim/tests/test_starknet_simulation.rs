#[cfg(test)]
mod tests {
    use cairo_vm::felt::Felt252;
    use dotenv::dotenv;
    use num_traits::Num;
    use protosim::starknet_simulation::{
        rpc_reader::RpcStateReader,
        simulation::{ContractOverride, SimulationEngine, SimulationParameters},
    };
    use rpc_state_reader::rpc_state::{RpcChain, RpcState};
    use starknet_api::block::BlockNumber;
    use starknet_in_rust::utils::{felt_to_hash, get_storage_var_address, Address, ClassHash};
    use std::{collections::HashMap, env, sync::Arc};

    const BOB_ADDRESS: &str = "065c19e14e2587d2de74c561b2113446ca4b389aabe6da1dc4accb6404599e99";
    const EKUBO_ADDRESS: &str = "00000005dd3d2f4429af886cd1a3b08289dbcea99a294197e9eb43b0e0325b4b";
    const USDC_ADDRESS: &str = "053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8";
    const USDT_ADDRESS: &str = "068f5c6a61780768455de69077e07e89787839bf8166decfbf92b645209c0fb8";
    const ETH_ADDRESS: &str = "049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";
    const DAI_ADDRESS: &str = "da114221cb83fa859dbdb4c44beeaa0bb37c7537ad5ae66fe5e0efd20e6eb3";

    fn string_to_address(address: &str) -> Address {
        Address(Felt252::from_str_radix(address, 16).expect("hex address"))
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

    #[allow(unused_variables)]
    fn setup_engine(
        block_number: u64,
        contract_overrides: Option<Vec<ContractOverride>>,
    ) -> SimulationEngine<RpcStateReader> {
        let rpc_state_reader = Arc::new(setup_reader(block_number));
        let contract_overrides = contract_overrides.unwrap_or_default();

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
    fn test_consecutive_simulations_ekubo() {
        // Test vars
        let block_number = 354168;
        let token0 = string_to_address(DAI_ADDRESS);
        let token1 = string_to_address(USDT_ADDRESS);
        let test_wallet = string_to_address(BOB_ADDRESS);
        let ekubo_address = string_to_address(EKUBO_ADDRESS);
        let sell_amount = Felt252::from_str_radix("3bf9da25c1bfd31da", 16).unwrap();

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
            token0.0,                                                              // token0
            token1.0,                                                              // token1
            Felt252::from_str_radix("5e59d28446cbf2061e33040400000", 16).unwrap(), // fee
            Felt252::from(10),                                                     // tick spacing
            Felt252::from(0),                                                      // extension
            // Swap data
            sell_amount,      // amount
            Felt252::from(0), // amount sign
            Felt252::from(0), // istoken1
            Felt252::from_str_radix("10c6cdcb20b7a5db24ca0ceb6980", 16).unwrap(), /* sqrt ratio
                               * limit */
            Felt252::from(0),
            Felt252::from(100), // skip ahead
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

    #[test]
    fn test_get_eth_usdc_spot_price_ekubo() {
        let block_number = 367676;
        let mut engine = setup_engine(block_number, None);

        let ekubo_address = string_to_address(EKUBO_ADDRESS);

        let swap_calldata = vec![
            Felt252::from_str_radix(ETH_ADDRESS, 16).unwrap(), // token0
            Felt252::from_str_radix(USDC_ADDRESS, 16).unwrap(), // token1
            Felt252::from_str_radix("170141183460469235273462165868118016", 10).unwrap(), // fee
            Felt252::from(1000),                               // tick spacing
            Felt252::from(0),                                  // extension
        ];

        let params = SimulationParameters::new(
            string_to_address(BOB_ADDRESS),
            ekubo_address,
            swap_calldata,
            "get_pool_price".to_owned(),
            None,
            Some(100000),
            block_number,
        );

        let result0 = engine.simulate(&params);

        let res = result0.unwrap().result[0].clone();

        // To get the human readable price we will need to convert this on the Python side like
        // this: https://www.wolframalpha.com/input?i=(14458875492015717597830515600275777+/+2**128)**2*10**12
        assert_eq!(res, Felt252::from_str_radix("14458875492015717597830515600275777", 10).unwrap())
    }

    #[test]
    fn test_get_dai_usdc_spot_price_ekubo() {
        let block_number = 367676;
        let mut engine = setup_engine(block_number, None);

        let ekubo_address = string_to_address(EKUBO_ADDRESS);

        let swap_calldata = vec![
            Felt252::from_str_radix(DAI_ADDRESS, 16).unwrap(), // token0
            Felt252::from_str_radix(USDC_ADDRESS, 16).unwrap(), // token1
            Felt252::from_str_radix("170141183460469235273462165868118016", 10).unwrap(), // fee
            Felt252::from(1000),                               // tick spacing
            Felt252::from(0),                                  // extension
        ];

        let params = SimulationParameters::new(
            string_to_address(BOB_ADDRESS),
            ekubo_address,
            swap_calldata,
            "get_pool_price".to_owned(),
            None,
            Some(100000),
            block_number,
        );

        let result0 = engine.simulate(&params);

        let res = result0.unwrap().result[0].clone();

        // To get the human readable price we will need to convert this on the Python side like
        // this: https://www.wolframalpha.com/input?i=(340321610937302884216160363291566+/+2**128)**2*10**12
        assert_eq!(res, Felt252::from_str_radix("340321610937302884216160363291566", 10).unwrap())
    }
}
