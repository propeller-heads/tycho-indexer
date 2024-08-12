import argparse
import asyncio
import aiohttp
import json
import os
from web3 import Web3
from hexbytes import HexBytes

rps = 1000
NODE_URLS = [
    os.getenv("ETH_RPC_URL")
]
current_node = 0


async def fetch_tycho_components(session, system: str) -> dict:
    payload = {"protocol_system": system}
    uri="http://127.0.0.1:4242/v1/ethereum/protocol_components"
    res = await session.post(
        uri,
        json=payload,
        headers={
         "Content-Type": "application/json",
         "Accept": "application/json"
    })
    protocol_components = (await res.json())["protocol_components"]
    return protocol_components


async def fetch_tycho_accounts(session, accounts: list[str], state_block: int) -> list[dict]:
    payload = {
        "contractIds": [{"address": addr, "chain": "ethereum"}for addr in accounts],
        "version": {"block": {"number": state_block, "chain": "ethereum"}}
    }
    uri="http://127.0.0.1:4242/v1/ethereum/contract_state"
    res = await session.post(
        uri,
        json=payload,
        headers={
         "Content-Type": "application/json",
         "Accept": "application/json"
    })
    accounts = (await res.json())["accounts"]
    return accounts



async def fetch_system_accounts(session, system: str, state_block: int) -> list[dict]:
    protocol_components = await fetch_tycho_components(session, system)
    contracts = [addr for pc in protocol_components for addr in pc["contract_ids"]]

    # Create batches of 50 contracts each
    batch_size = 50
    batches = [contracts[i:i + batch_size] for i in range(0, len(contracts), batch_size)]

    # Asynchronously fetch account data for each batch
    tasks = [fetch_tycho_accounts(session, batch, state_block) for batch in batches]
    results = await asyncio.gather(*tasks)

    # Flatten the list of lists to a single list of accounts
    all_accounts = [account for sublist in results for account in sublist]
    return all_accounts



async def fetch_storage_value(session, address, slot, block_number, retry=0):
    global current_node
    
    # Switch to the next node URL in round-robin fashion to not exceed rate limit.
    node_url = NODE_URLS[current_node]
    current_node = (current_node + 1) % len(NODE_URLS)
    
    payload = json.dumps({
        "jsonrpc": "2.0",
        "method": "eth_getStorageAt",
        "params": [address, slot, hex(block_number)],
        "id": 1
    })
    headers = {'Content-Type': 'application/json'}
    try:
        async with session.post(node_url, data=payload, headers=headers) as response:
            response_json = await response.json()
            if 'result' in response_json:
                return response_json['result']
            else:
                print(f"fail for address {address}, slot {slot}: {response_json}")
                raise Exception("Failed to get storage value")
    except Exception as e:
        if retry < 3:  # Retry up to 3 times
            await asyncio.sleep(2 ** retry)  # Exponential backoff
            return await fetch_storage_value(session, address, slot, block_number, retry + 1)
        else:
            print(f"Final fail for address {address}, slot {slot}: {e}")
            return None

                
async def validate_account_storage(session, account, block_number, rps=9):
        address = Web3.toChecksumAddress(account['address'])
        tasks = []
        for slot, expected_value in account['slots'].items():
            tasks.append(fetch_storage_value(session, address, slot, block_number))
        
        # Throttling to stay under the rate limit
        actual_values = []
        while tasks:
            batch, tasks = tasks[:rps], tasks[rps:]
            results = await asyncio.gather(*batch)
            actual_values.extend(results)
            await asyncio.sleep(1)  # Wait for 1 second before the next batch

        invalid_slots = {}
        for i, (slot, expected_value) in enumerate(account['slots'].items()):
            actual_value = actual_values[i]
            if actual_value != expected_value:
                # Record the slot and the discrepancies
                invalid_slots[slot] = {'expected': expected_value, 'actual': actual_value}

        # Print the summary for the account
        if invalid_slots:
            print(f"Account {account['address']} INVALID. Diffs:")
            for slot, diff in invalid_slots.items():
                print(f"  Slot {slot}: Expected {diff['expected']}, Got {diff['actual']}")
        else:
            print(f"Account {account['address']} is VALID.")


async def main():
    parser = argparse.ArgumentParser(description='Compare protocol account state.')
    # Add arguments
    parser.add_argument('system', help='The protocol system whose contracts to compare.')
    parser.add_argument('block_number', type=int, help='The block state to query.')
    # Parse arguments
    args = parser.parse_args()
    # Use the parsed arguments
    block_number = args.block_number
    system = args.system

    async with aiohttp.ClientSession() as session:
        # Load your data from tycho
        print("Loading data from tycho")
        accounts = await fetch_system_accounts(session, system, block_number)
        print(f"Got: {len(accounts)} accounts")

        # Validate each account
        print("Starting comparison...")
        for account in accounts:
            print(f"Validating {account['address']} with {len(account['slots'])} slots...")
            await validate_account_storage(session, account, block_number, rps)

# Run the main function
asyncio.run(main())

