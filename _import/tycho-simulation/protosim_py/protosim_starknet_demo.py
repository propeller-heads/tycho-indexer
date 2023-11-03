"""Example of running a Starknet simulation in Rust from Python.

(Build and) install the `protosim_py` package in your Python before running this.
See the Readme.md file for instructions.
"""

import os
from protosim_py import (
    StarknetSimulationEngine,
    StarknetSimulationParameters,
)
from dotenv import load_dotenv
import logging
FORMAT = '%(levelname)s %(name)s %(asctime)-15s %(filename)s:%(lineno)d %(message)s'
logging.basicConfig(format=FORMAT)
logging.getLogger().setLevel(logging.INFO)

U256MAX = 115792089237316195423570985008687907853269984665640564039457584007913129639935


def test_starknet_simulation():
    print("Running Starknet simulation")

    # Load api key from env variable or .env file
    load_dotenv()
    infura_api_key = os.getenv("INFURA_API_KEY")
    if infura_api_key is None:
        raise Exception("INFURA_API_KEY env variable is not set")

    engine = StarknetSimulationEngine(
        rpc_endpoint=f"https://starknet-mainnet.infura.io/v3/{infura_api_key}",
        feeder_url="https://alpha-mainnet.starknet.io/feeder_gateway",
        contract_overrides=[],
    )

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


if __name__ == "__main__":
    test_starknet_simulation()
