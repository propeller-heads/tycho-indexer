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

    const BOB_ADDRESS: &str = "0x065c19e14e2587d2de74c561b2113446ca4b389aabe6da1dc4accb6404599e99";
    const EKUBO_ADDRESS: &str =
        "0x00000005dd3d2f4429af886cd1a3b08289dbcea99a294197e9eb43b0e0325b4b";
    const EKUBO_SIMPLE_SWAP_ADDRESS: &str =
        "0x07a83729aaaae6344d6fca558614cd22ecdd3f5cd90ec0cd20c8d6bf08170431";
    const USDC_ADDRESS: &str = "0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8";
    const ETH_ADDRESS: &str = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";
    const DAI_ADDRESS: &str = "0xda114221cb83fa859dbdb4c44beeaa0bb37c7537ad5ae66fe5e0efd20e6eb3";

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
            hex::decode("02760f25d5a4fb2bdde5f561fd0b44a3dee78c28903577d37d669939d97036a0")
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap();

        let mut storage_overrides = HashMap::new();

        // override balance
        let balance_storage_hash =
            felt_to_hash(&get_storage_var_address("ERC20_balances", &[wallet.0.clone()]).unwrap());
        storage_overrides.insert((wallet.clone(), balance_storage_hash), sell_amount.clone());

        // override allowance
        let allowance_storage_hash = felt_to_hash(
            &get_storage_var_address("ERC20_allowances", &[wallet.0.clone(), spender.0]).unwrap(),
        );
        storage_overrides.insert((wallet, allowance_storage_hash), sell_amount);

        let token_contract =
            ContractOverride::new(sell_token, class_hash, None, Some(storage_overrides));

        vec![token_contract]
    }

    #[test]
    #[cfg_attr(not(feature = "network_tests"), ignore)]
    fn test_consecutive_simulations_ekubo() {
        // Test vars
        let block_number = 194554;
        let token0 = address_str(DAI_ADDRESS);
        let token1 = address_str(ETH_ADDRESS);
        let test_wallet = address_str(BOB_ADDRESS);
        let ekubo_address = address_str(EKUBO_SIMPLE_SWAP_ADDRESS);
        let sell_amount = felt_str("0x5afb5ab61ef191");

        // Contruct engine with sell token override
        let contract_overrides = construct_token_overrides(
            test_wallet.clone(),
            token0.clone(),
            sell_amount.clone(),
            ekubo_address.clone(),
        );
        let mut engine = setup_engine(block_number, Some(contract_overrides));

        // obtained from this Ekubo simple swap call: https://starkscan.co/call/0x04857b5a7af37e9b9f6fae27923d725f07016a4449f74f5ab91c04f13bbc8d23_1_3
        let swap_calldata = vec![
            // Pool key data
            token0.0,                                     // token0
            token1.0,                                     // token1
            felt_str("0xc49ba5e353f7d00000000000000000"), // fee
            Felt252::from(5982),                          // tick spacing
            Felt252::from(0),                             // extension
            // Swap data
            sell_amount,                                   // amount
            Felt252::from(0),                              // amount sign
            Felt252::from(0),                              // istoken1
            felt_str("0x65740af99bee7b4bf062fb147160000"), // sqrt ratio limit (lower bits
            Felt252::from(0),                              // sqrt ratio limit (upper bits)
            Felt252::from(0),                              // skip ahead
            test_wallet.0.clone(),                         // recipient
            Felt252::from(0),                              // calculated_amount_threshold
        ];

        let params = SimulationParameters::new(
            test_wallet,
            ekubo_address,
            swap_calldata,
            "swap".to_owned(),
            None,
            Some(u128::MAX),
            block_number,
        );

        let result0 = engine.simulate(&params);

        dbg!(&result0);

        assert!(result0.is_ok())
    }

    #[test]
    fn test_get_eth_usdc_spot_price_ekubo() {
        let block_number = 367676;
        let mut engine = setup_engine(block_number, None);

        let ekubo_address = address_str(EKUBO_ADDRESS);

        let swap_calldata = vec![
            felt_str(ETH_ADDRESS),                            // token0
            felt_str(USDC_ADDRESS),                           // token1
            felt_str("170141183460469235273462165868118016"), // fee
            Felt252::from(1000),                              // tick spacing
            Felt252::from(0),                                 // extension
        ];

        let params = SimulationParameters::new(
            address_str(BOB_ADDRESS),
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
        assert_eq!(res, felt_str("14458875492015717597830515600275777"))
    }

    #[test]
    fn test_get_dai_usdc_spot_price_ekubo() {
        let block_number = 367676;
        let mut engine = setup_engine(block_number, None);

        let ekubo_address = address_str(EKUBO_ADDRESS);

        let swap_calldata = vec![
            felt_str(DAI_ADDRESS),                            // token0
            felt_str(USDC_ADDRESS),                           // token1
            felt_str("170141183460469235273462165868118016"), // fee
            Felt252::from(1000),                              // tick spacing
            Felt252::from(0),                                 // extension
        ];

        let params = SimulationParameters::new(
            address_str(BOB_ADDRESS),
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
        assert_eq!(res, felt_str("340321610937302884216160363291566"))
    }
}
