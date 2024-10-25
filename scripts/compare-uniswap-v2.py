import os
import json
import argparse
from web3 import Web3

# Parse command-line arguments
parser = argparse.ArgumentParser(
    description="Compare Uniswap V2 pool data with historical data."
)
parser.add_argument("block_number", type=int, help="The target block number to query.")
args = parser.parse_args()

target_block_number = args.block_number

# Reading the JSON data from the file
json_file = f"uniswap_v2_{target_block_number}.json"
if not os.path.exists(json_file):
    raise FileNotFoundError(f"JSON file {json_file} not found.")

with open(json_file, "r") as file:
    parsed_data = json.load(file)

# RPC URL
ETH_RPC_URL = os.getenv("ETH_RPC_URL")
if not ETH_RPC_URL:
    raise ValueError("ETH_RPC_URL environment variable not set")

web3 = Web3(Web3.HTTPProvider(ETH_RPC_URL))

# ABI to interact with UniswapV2 pool to get reserves
pool_abi = [
    {
        "constant": True,
        "inputs": [],
        "name": "getReserves",
        "outputs": [
            {"internalType": "uint112", "name": "reserve0", "type": "uint112"},
            {"internalType": "uint112", "name": "reserve1", "type": "uint112"},
            {"internalType": "uint32", "name": "blockTimestampLast", "type": "uint32"},
        ],
        "payable": False,
        "stateMutability": "view",
        "type": "function",
    }
]

# ABI for ERC20 balanceOf method
erc20_abi = [
    {
        "constant": True,
        "inputs": [{"internalType": "address", "name": "owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function",
    }
]


def decode_big_endian(hex_str, signed=False):
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    # Convert hex string to bytes in big endian
    value_bytes = bytes.fromhex(hex_str)
    return int.from_bytes(value_bytes, byteorder="big", signed=signed)


def get_token_balance(token_address, pool_address, block_number):
    """Query the token balance of a pool at a specific block."""
    token_contract = web3.eth.contract(
        address=web3.to_checksum_address(token_address), abi=erc20_abi
    )
    return token_contract.functions.balanceOf(pool_address).call(
        block_identifier=block_number
    )


def compare_pool_data(pool, target_block_number):
    component_id = web3.to_checksum_address(pool["component_id"])
    contract = web3.eth.contract(address=component_id, abi=pool_abi)

    # Get reserves
    reserves = contract.functions.getReserves().call(
        block_identifier=target_block_number
    )

    local_reserve0 = decode_big_endian(pool["attributes"]["reserve0"])
    local_reserve1 = decode_big_endian(pool["attributes"]["reserve1"])

    # Get balances:
    token0_address = list(pool["balances"].keys())[0]
    token1_address = list(pool["balances"].keys())[1]
    balance0 = get_token_balance(token0_address, component_id, target_block_number)
    balance1 = get_token_balance(token1_address, component_id, target_block_number)

    local_balance0 = decode_big_endian(pool["balances"][token0_address])
    local_balance1 = decode_big_endian(pool["balances"][token1_address])

    # Initialize a variable to track if there are differences
    has_diff = False
    diff_messages = []

    # Check for differences in reserve0
    if local_reserve0 != reserves[0]:
        diff_messages.append(
            f"Local reserve0: {local_reserve0}, Historical reserve0: {reserves[0]}"
        )
        has_diff = True

    # Check for differences in reserve1
    if local_reserve1 != reserves[1]:
        diff_messages.append(
            f"Local reserve1: {local_reserve1}, Historical reserve1: {reserves[1]}"
        )
        has_diff = True

    # Check for differences in balance0
    if local_balance0 != balance0:
        diff_messages.append(
            f"Local balance0: {local_balance0}, Historical balance0: {balance0}"
        )
        has_diff = True

    # Check for differences in balance1
    if local_balance1 != balance1:
        diff_messages.append(
            f"Local balance1: {local_balance1}, Historical balance1: {balance1}"
        )
        has_diff = True

    if has_diff:
        print(f"Differences found in {pool['component_id']}:")
        # If there are differences, print them
        for msg in diff_messages:
            print(msg)
    else:
        print(f"No differences found in {pool['component_id']}.")

    print("---")


for state in parsed_data["states"]:
    compare_pool_data(state, target_block_number)
