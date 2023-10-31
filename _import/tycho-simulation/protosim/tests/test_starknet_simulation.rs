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
    use starknet_in_rust::utils::{Address, ClassHash};
    use std::{env, sync::Arc};

    fn string_to_address(address: &str) -> Address {
        Address(Felt252::from_str_radix(address, 16).expect("hex address"))
    }

    fn setup_reader(block_number: u64) -> RpcStateReader {
        dotenv().expect("Missing .env file");
        let rpc_endpoint = format!(
            "https://{}.infura.io/v3/{}",
            RpcChain::MainNet,
            env::var("INFURA_API_KEY").expect("missing infura api key")
        );
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
        token0: Address,
        token1: Address,
    ) -> SimulationEngine<RpcStateReader> {
        let rpc_state_reader = Arc::new(setup_reader(block_number));

        // // Ekubo contract
        // let address =
        //     string_to_address("00000005dd3d2f4429af886cd1a3b08289dbcea99a294197e9eb43b0e0325b4b");
        // let class_hash: ClassHash =
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
        let mut engine = setup_engine(block_number, token0, token1);

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
            Felt252::from_str_radix("340269419829709255939292639488384", 16).unwrap(), // sqrt ratio limit
            Felt252::from(0),
            Felt252::from(100), // skip ahead
        ];

        let params = SimulationParameters::new(
            string_to_address("065c19e14e2587d2de74c561b2113446ca4b389aabe6da1dc4accb6404599e99"), // caller used in other tests
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
