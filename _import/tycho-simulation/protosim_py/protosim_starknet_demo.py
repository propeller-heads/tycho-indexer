"""Example of running a Starknet simulation in Rust from Python.

(Build and) install the `protosim_py` package in your Python before running this.
See the Readme.md file for instructions.
"""

import os
from protosim_py import (
    StarknetSimulationEngine,
    StarknetSimulationParameters,
    StarknetContractOverride,
)
from dotenv import load_dotenv
import logging
FORMAT = '%(levelname)s %(name)s %(asctime)-15s %(filename)s:%(lineno)d %(message)s'
logging.basicConfig(format=FORMAT)
logging.getLogger().setLevel(logging.INFO)

U256MAX = 115792089237316195423570985008687907853269984665640564039457584007913129639935
U128MAX = 340282366920938463463374607431768211455

# Addresses as constants
BOB_ADDRESS = "0x065c19e14e2587d2de74c561b2113446ca4b389aabe6da1dc4accb6404599e99"
EKUBO_ADDRESS = "0x00000005dd3d2f4429af886cd1a3b08289dbcea99a294197e9eb43b0e0325b4b"
EKUBO_SIMPLE_SWAP_ADDRESS = "0x07a83729aaaae6344d6fca558614cd22ecdd3f5cd90ec0cd20c8d6bf08170431"
USDC_ADDRESS = "0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8"
ETH_ADDRESS = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"
DAI_ADDRESS = "0xda114221cb83fa859dbdb4c44beeaa0bb37c7537ad5ae66fe5e0efd20e6eb3"


def setup_engine(contract_overrides: list = None) -> StarknetSimulationEngine:
    load_dotenv()
    infura_api_key = os.getenv("INFURA_API_KEY")
    if infura_api_key is None:
        raise Exception("INFURA_API_KEY env variable is not set")

    contract_overrides = contract_overrides if contract_overrides is not None else []
    engine = StarknetSimulationEngine(
        rpc_endpoint=f"https://starknet-mainnet.infura.io/v3/{infura_api_key}",
        feeder_url="https://alpha-mainnet.starknet.io/feeder_gateway",
        contract_overrides=contract_overrides,
    )
    return engine


def test_starknet_approve_simulation():
    print("Running Starknet simulation")

    # Load api key from env variable or .env file
    engine = setup_engine()

    params = StarknetSimulationParameters(
        caller="0x035fc5a31b2cf06af3a7e9b9b00a508b72dea342277c7415b770fbd69a6c5933",
        to="0x022b05f9396d2c48183f6deaf138a57522bcc8b35b67dee919f76403d1783136",
        data=[
            467359278613506166151492726487752216059557962335532790304583050955123345960,
            62399604864,
            0
        ],
        entry_point="approve",
        block_number=366118,
    )

    print("Running simulation")
    result = engine.run_sim(params)
    print("Simulation result:")
    print(f"result: {result.result=}")
    print(f"states_updates: {result.states_updates=}")
    print(f"gas_used: {result.gas_used=}")

# Test consecutive simulations
def test_starknet_swap_simulation():
    block_number = 194554
    token0 = DAI_ADDRESS
    token1 = ETH_ADDRESS
    test_wallet = BOB_ADDRESS
    ekubo_swap_address = EKUBO_SIMPLE_SWAP_ADDRESS
    ekubo_core_address = EKUBO_ADDRESS
    sell_amount = "0x5afb5ab61ef191"

    # Construct engine with contract overrides
    sell_token_contract_override = StarknetContractOverride(
        token0, "0x02760f25d5a4fb2bdde5f561fd0b44a3dee78c28903577d37d669939d97036a0", None)
    engine = setup_engine([sell_token_contract_override])

    # Construct simulation parameters
    storage_overrides = {
        (token0, int("2039938672845109684464553252816414832543773106309397125013760479565072283554")): int("25609114925068689"),
        (token0, int("1919009528300487416898558168639787817852314761514939568475739027942176236393")): int("2421600066015287788594"),
    }
    params = StarknetSimulationParameters(
        caller=test_wallet,
        to=ekubo_swap_address,
        data=[
            int(token0, 16),
            int(token1, 16),
            int("0xc49ba5e353f7d00000000000000000", 16),
            5982,
            0,
            int(sell_amount, 16),
            0,
            0,
            int("0x65740af99bee7b4bf062fb147160000", 16),
            0,
            0,
            int(test_wallet, 16),
            0,
        ],  # Call data for the swap
        entry_point="swap",
        overrides=storage_overrides,
        block_number=block_number,
        gas_limit=U128MAX,
    )

    # Run simulation
    result = engine.run_sim(params)
    assert result.gas_used == 9480810
    assert result.result[2] == 21909951468890105

    # Run simulation again
    # Running the simulation should not persist any state changes, so running it again should give the same result
    result = engine.run_sim(params)
    assert result.gas_used == 9480810
    assert result.result[2] == 21909951468890105

if __name__ == "__main__":
    test_starknet_approve_simulation()

    test_starknet_swap_simulation()
