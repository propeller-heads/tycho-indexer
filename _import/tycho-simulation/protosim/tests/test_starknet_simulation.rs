#[cfg(test)]
mod tests {
    use cairo_vm::felt::Felt252;
    use dotenv::dotenv;
    use num_traits::Num;
    use protosim::starknet_simulation::{
        rpc_reader::RpcStateReader,
        simulation::{SimulationEngine, SimulationParameters},
    };
    use rpc_state_reader::rpc_state::{RpcChain, RpcState};
    use starknet_api::block::BlockNumber;
    use starknet_in_rust::utils::Address;
    use std::{env, sync::Arc};

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
        token0: Option<Address>,
        token1: Option<Address>,
    ) -> SimulationEngine<RpcStateReader> {
        let rpc_state_reader = Arc::new(setup_reader(block_number));

        // // Ekubo contract
        // let address =
        //     string_to_address("00000005dd3d2f4429af886cd1a3b08289dbcea99a294197e9eb43b0e0325b4b"
        // ); let class_hash: ClassHash =
        //     hex::decode("008e44da7924f4807d4200f8ff9938182e0bd6841dcb62ef397fcfd7fb2ff1e0")
        //         .unwrap()
        //         .as_slice()
        //         .try_into()
        //         .unwrap();
        // let abi_path = "tests/resources/ekubo.json";
        // let ekubo_contract =
        //     ContractOverride::new(address, class_hash, Some(abi_path.to_owned()), None);

        // ERC20 contract overrides

        let contract_overrides = vec![];

        SimulationEngine::new(rpc_state_reader, contract_overrides).unwrap()
    }

    #[test]
    fn test_consecutive_simulations_ekubo() {
        // create engine with mocked erc20 token contracts
        let block_number = 354168;
        let token0 =
            string_to_address("da114221cb83fa859dbdb4c44beeaa0bb37c7537ad5ae66fe5e0efd20e6eb3");
        let token1 =
            string_to_address("068f5c6a61780768455de69077e07e89787839bf8166decfbf92b645209c0fb8");
        let mut engine = setup_engine(block_number, Some(token0), Some(token1));

        let ekubo_address =
            string_to_address("00000005dd3d2f4429af886cd1a3b08289dbcea99a294197e9eb43b0e0325b4b");

        // obtained from this Ekubo core swap call: https://voyager.online/tx/0x634fa25f6b3fb6aceffbf689edb04eb24d4eb118a955d3439382a231e78b7e7#internalCalls
        let swap_calldata = vec![
            // Pool key data
            Felt252::from_str_radix(
                "385291772725090318157700937045086145273563247402457518748197066808155336371",
                16,
            )
            .unwrap(), // token0
            Felt252::from_str_radix(
                "2967174050445828070862061291903957281356339325911846264948421066253307482040",
                16,
            )
            .unwrap(), // token1
            Felt252::from_str_radix("30618607375546000000000000000000000", 16).unwrap(), // fee
            Felt252::from(10), // tick spacing
            Felt252::from(0),  // extension
            // Swap data
            Felt252::from_str_radix("69147602770206732762", 16).unwrap(), // amount
            Felt252::from(0),                                             // amount sign
            Felt252::from(0),                                             // istoken1
            Felt252::from_str_radix("340269419829709255939292639488384", 16).unwrap(), /* sqrt ratio limit */
            Felt252::from(0),
            Felt252::from(100), // skip ahead
        ];

        let params = SimulationParameters::new(
            string_to_address("065c19e14e2587d2de74c561b2113446ca4b389aabe6da1dc4accb6404599e99"), /* caller used in other tests */
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
        let mut engine = setup_engine(block_number, None, None);

        let ekubo_address =
            string_to_address("00000005dd3d2f4429af886cd1a3b08289dbcea99a294197e9eb43b0e0325b4b");

        let swap_calldata = vec![
            Felt252::from_str_radix(
                "2087021424722619777119509474943472645767659996348769578120564519014510906823",
                10,
            )
            .unwrap(), // token0
            Felt252::from_str_radix(
                "2368576823837625528275935341135881659748932889268308403712618244410713532584",
                10,
            )
            .unwrap(), // token1
            Felt252::from_str_radix("170141183460469235273462165868118016", 10).unwrap(), // fee
            Felt252::from(1000), // tick spacing
            Felt252::from(0),    // extension
        ];

        let params = SimulationParameters::new(
            string_to_address("065c19e14e2587d2de74c561b2113446ca4b389aabe6da1dc4accb6404599e99"), /* caller used in other tests */
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
        let mut engine = setup_engine(block_number, None, None);

        let ekubo_address =
            string_to_address("00000005dd3d2f4429af886cd1a3b08289dbcea99a294197e9eb43b0e0325b4b");

        let swap_calldata = vec![
            Felt252::from_str_radix(
                "385291772725090318157700937045086145273563247402457518748197066808155336371",
                10,
            )
            .unwrap(), // token0
            Felt252::from_str_radix(
                "2368576823837625528275935341135881659748932889268308403712618244410713532584",
                10,
            )
            .unwrap(), // token1
            Felt252::from_str_radix("170141183460469235273462165868118016", 10).unwrap(), // fee
            Felt252::from(1000), // tick spacing
            Felt252::from(0),    // extension
        ];

        let params = SimulationParameters::new(
            string_to_address("065c19e14e2587d2de74c561b2113446ca4b389aabe6da1dc4accb6404599e99"), /* caller used in other tests */
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
