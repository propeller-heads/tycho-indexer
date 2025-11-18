import os
import logging as log
from web3 import Web3
from web3.types import TxParams
import requests
import argparse
from eth_abi.abi import decode as abi_decode

node_url = os.getenv("RPC_URL")
the_graph_key = os.getenv("THE_GRAPH_API_KEY")
web3 = Web3(Web3.HTTPProvider(node_url))
GRAPH_URL = f'https://gateway.thegraph.com/api/{the_graph_key}/subgraphs/id/GENunSHWLBXm59mBSgPzQ8metBEp9YDfdqwFr91Av1UM'


log.basicConfig(
    format="{asctime} - {levelname} - {message}",
    style="{",
    datefmt="%Y-%m-%d %H:%M",
    level=log.INFO,
)

"""
This script verifies protocols that use observations and ticks by comparing them
against on-chain values at a specified block. Any mismatch indicates inconsistent protocol state.
"""

def fetch_all_protocol_components(tvl_gt: int):
    all_results = []
    uri = "http://0.0.0.0:4242/v1/protocol_components"
    page = 0
    page_size = 500

    while True:
        payload = {
            "chain": "base",
            "pagination": {
                "page": page,
                "page_size": page_size
            },
            "tvl_gt": tvl_gt,
            "protocol_system": "aerodrome_slipstreams"
        }

        res = requests.post(
            uri,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
        )

        data = res.json()
        results = data.get("protocol_components", [])
        all_results.extend(results)

        if len(results) < page_size:
            break

        page += 1

    return all_results

def fetch_tycho_data(block: int, component_ids: list[str], page_size: int = 100):
    all_results = []
    uri = "http://0.0.0.0:4242/v1/protocol_state"

    # Split component_ids into chunks of 'page_size'
    for component_chunk in chunked_list(component_ids, page_size):
        page = 0
        while True:
            payload = {
                "protocolIds": [
                    {
                        "chain": "base",
                        "id": cid
                    } for cid in component_chunk
                ],
                "chain": "base",
                "include_balances": True,
                "protocol_system": "aerodrome_slipstreams",
                "version": {
                    "block": {
                        "chain": "base",
                        "number": block
                    }
                },
                "pagination": {
                    "page": page,
                    "page_size": page_size
                }
            }

            # Make the request
            res = requests.post(
                uri,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }
            )

            # Parse the response
            data = res.json()
            all_results.extend(data.get("states", []))

            # Break if there are no more pages (page_size < 100 indicates the end)
            if len(data.get("states", [])) < page_size:
                break

            # Move to the next page
            page += 1

    return all_results

def fetch_pool_ticks(pool_id, block_number=None):
    query = """
    query ($poolId: ID!, $blockNumber: Int) {
      pool(id: $poolId, block: {number: $blockNumber}) {
        id
        liquidity
        tick
        sqrtPrice
        ticks {
          liquidityNet
          tickIdx
        }
      }
    }
    """
    variables = {"poolId": pool_id, "blockNumber": block_number}

    for i in range(5):
        response = requests.post(GRAPH_URL, json={'query': query, 'variables': variables})
        if response.status_code == 200:
            if response.json()['data']['pool'] is not None:
                return response.json()['data']['pool']
            else:
                continue
        else:
            print(f"Error fetching data for pool {pool_id}: {response.status_code}")
            return None

def decode_observation_bytes(raw_bytes: bytes):
    if len(raw_bytes) != 32:
        raise ValueError(f"Invalid observation length: expected 32 bytes, got {len(raw_bytes)}")

    value = int.from_bytes(raw_bytes, "big")

    # 1. blockTimestamp uint32
    block_timestamp = value & ((1 << 32) - 1)

    # 2. tickCumulative int56
    tick_bits = (value >> 32) & ((1 << 56) - 1)
    tick_cumulative = tick_bits - (1 << 56) if tick_bits & (1 << 55) else tick_bits

    # 3. uint160
    seconds_per_liquidity = (value >> 88) & ((1 << 160) - 1)

    # 4. initialized bool
    initialized = ((value >> 248) & 1) == 1

    return {
        "block_timestamp": block_timestamp,
        "tick_cumulative": tick_cumulative,
        "seconds_per_liquidity": seconds_per_liquidity,
        "initialized": initialized,
    }

OBSERVATION_OUTPUT_TYPES = ["uint32", "int56", "uint160", "bool"]

def hex_to_int(hex_str, signed=False):
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    # Convert hex string to bytes in little endian
    value_bytes_little = bytes.fromhex(hex_str)
    return int.from_bytes(value_bytes_little, byteorder='big', signed=signed)

def decode_batch_observations(hex_results):
    decoded = []

    for r in hex_results:
        # Convert HexBytes or bytes into hex string WITHOUT 0x
        if hasattr(r, "hex"):
            hex_str = r.hex()
        else:
            hex_str = str(r)
            if hex_str.startswith("0x"):
                hex_str = hex_str[2:]

        raw = bytes.fromhex(hex_str)

        o = abi_decode(OBSERVATION_OUTPUT_TYPES, raw)
        decoded.append({
            "block_timestamp": o[0],
            "tick_cumulative": o[1],
            "seconds_per_liquidity": o[2],
            "initialized": o[3]
        })

    return decoded


OBSERVATION_ABI = [{
    "constant": True,
    "inputs": [{"name": "", "type": "uint256"}],
    "name": "observations",
    "outputs": [
        {"name": "blockTimestamp", "type": "uint32"},
        {"name": "tickCumulative", "type": "int56"},
        {"name": "secondsPerLiquidity", "type": "uint160"},
        {"name": "initialized", "type": "bool"}
    ],
    "stateMutability": "view",
    "type": "function"
}]

def get_observation_contract(pool_addr):
    return web3.eth.contract(
        address=Web3.to_checksum_address(pool_addr),
        abi=OBSERVATION_ABI
    )

def batch_fetch_observations(pool_addr, indices, block_number):
    pool_checksum = Web3.to_checksum_address(pool_addr)
    selector = web3.keccak(text="observations(uint256)")[:4]

    results = []
    batch_size = 100

    for i in range(0, len(indices), batch_size):
        chunk = indices[i:i + batch_size]

        with web3.batch_requests() as batch:
            reqs = []

            for idx in chunk:
                call_tx: TxParams = {
                    "to": pool_checksum,
                    "data": Web3.to_hex(selector + idx.to_bytes(32, "big")),
                }
                reqs.append(batch.add(web3.eth.call(call_tx, block_identifier=block_number)))

            responses = batch.execute()

        results.extend(responses)

    return results

def compare_pools(local_pool_data, fetched_pool_ticks_data, block_number):
    pool_addr = local_pool_data["component_id"]
    attrs = local_pool_data["attributes"]

    differences = {}

    observation_indices = []
    for key in attrs:
        if key.startswith("observations/"):
            idx = int(key.split("/")[1])
            observation_indices.append(idx)

    obs_results_hex = batch_fetch_observations(pool_addr, observation_indices, block_number)
    decoded_onchain_obs = decode_batch_observations(obs_results_hex)

    for idx, onchain_obj in zip(observation_indices, decoded_onchain_obs):
        key = f"observations/{idx}"
        local_hex = attrs[key]

        raw = bytes.fromhex(local_hex[2:])
        local_obj = decode_observation_bytes(raw)

        if local_obj != onchain_obj:
            differences[key] = (local_obj, onchain_obj)
        # else:
        #     print("✅ Observation", idx, "is correct, ", "Tycho: ", local_obj, "Onchain: ", onchain_obj)

    for key, val_hex in attrs.items():
        # ticks
        if key.startswith("ticks/") and key.endswith("/net-liquidity"):
            tick_idx = int(key.split("/")[1])
            liquidity_net = hex_to_int(val_hex, True)
            # Find corresponding tick in fetched data
            fetched_tick = next((tick for tick in fetched_pool_ticks_data['ticks'] if int(tick['tickIdx']) == tick_idx), None)
            if fetched_tick is not None:
                if int(fetched_tick['liquidityNet']) != liquidity_net:
                    differences[key] = (liquidity_net, int(fetched_tick['liquidityNet']))
                # else:
                #     print("✅ Tick", tick_idx, "is correct, ", "Tycho: ", val_hex, "Onchain: ", int(fetched_tick['liquidityNet']))

    return differences

def chunked_list(lst, n):
    """Splits the input list `lst` into chunks of size `n`."""
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


def hex_to_signed_int(hex_str):
    # Remove '0x' prefix and convert to bytes
    hex_val = hex_str[2:]
    bytes_val = bytes.fromhex(hex_val)
    # Convert bytes to signed integer (big-endian)
    return int.from_bytes(bytes_val, byteorder="big", signed=True)

def main():
    parser = argparse.ArgumentParser(description='Compare slipstreams protocol observations state.')
    # Add arguments
    parser.add_argument('tvl_gt', type=int, help='The minimum TVL to filter')
    parser.add_argument('block_number', type=int, help='The block state to query')
    parser.add_argument('pools', nargs='*',default=[],help='A list of component ids (pool addresses)')
    # Parse arguments
    args = parser.parse_args()
    # Use the parsed arguments
    tvl_gt = args.tvl_gt
    block_number = args.block_number
    pool_addresses = args.pools

    if len(pool_addresses) == 0:
        pool_addresses = [pc["id"] for pc in fetch_all_protocol_components(tvl_gt)]

    parsed_data = fetch_tycho_data(block_number, pool_addresses)
    for pool in parsed_data:
        pool_id = pool["component_id"]
        pool_ticks_data = fetch_pool_ticks(pool_id, block_number)
        differences = compare_pools(pool, pool_ticks_data, block_number)

        if differences:
            print(f"\nDifferences found for pool {pool_id}:")
            for key, (local_val, fetched_val) in differences.items():
                print(f"  {key}:")
                print(f"    Local:   {local_val}")
                print(f"    Onchain: {fetched_val}")
        else:
            print(f"✅ No differences found for pool {pool_id}.")

if __name__ == "__main__":
    main()
