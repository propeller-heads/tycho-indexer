#!/usr/bin/env python3
"""
Test script for the updated Tycho RPC client.
This script tests all the available endpoints to ensure they work correctly.
"""

import sys
import os

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tycho_indexer_client import (
    TychoRPCClient,
    TychoRPCError,
    Chain,
    ProtocolComponentsParams,
    ProtocolStateParams,
    ContractStateParams,
    TokensParams,
    ProtocolSystemsParams,
    ComponentTvlParams,
    TracedEntryPointParams,
    PaginationParams,
)


def test_client():
    """Test the updated Tycho RPC client."""

    # Initialize client
    client = TychoRPCClient(
        rpc_url="https://tycho-beta.propellerheads.xyz",
        chain=Chain.ethereum,
        auth_token="sampletoken",
    )

    print("Testing Tycho RPC Client...")
    print("=" * 50)

    try:
        # Test health endpoint
        print("1. Testing health endpoint...")
        health = client.health()
        print(f"   Health status: {health}")
        print()

        # Test protocol systems endpoint
        print("2. Testing protocol systems endpoint...")
        systems_params = ProtocolSystemsParams(
            chain=Chain.ethereum, pagination=PaginationParams(page=0, page_size=10)
        )
        systems = client.get_protocol_systems(systems_params)
        print(f"   Found {len(systems.protocol_systems)} protocol systems")
        print(
            f"   Pagination: page {systems.pagination.page}, size {systems.pagination.page_size}, total {systems.pagination.total}"
        )
        if systems.protocol_systems:
            print(f"   First system: {systems.protocol_systems[0]}")
        print()

        # Test tokens endpoint
        print("3. Testing tokens endpoint...")
        tokens_params = TokensParams(
            min_quality=10,
            traded_n_days_ago=30,
            pagination=PaginationParams(page=0, page_size=5),
        )
        tokens = client.get_tokens(tokens_params)
        print(f"   Found {len(tokens.tokens)} tokens")
        print(
            f"   Pagination: page {tokens.pagination.page}, size {tokens.pagination.page_size}, total {tokens.pagination.total}"
        )
        if tokens.tokens:
            print(
                f"   First token: {tokens.tokens[0].symbol} ({tokens.tokens[0].address.hex()})"
            )
        print()

        # Test protocol components endpoint (if we have a protocol system)
        if systems.protocol_systems:
            print("4. Testing protocol components endpoint...")
            components_params = ProtocolComponentsParams(
                protocol_system=systems.protocol_systems[0],
                pagination=PaginationParams(page=0, page_size=5),
            )
            components = client.get_protocol_components(components_params)
            print(f"   Found {len(components.protocol_components)} protocol components")
            print(
                f"   Pagination: page {components.pagination.page}, size {components.pagination.page_size}, total {components.pagination.total}"
            )
            if components.protocol_components:
                print(f"   First component: {components.protocol_components[0].id}")
            print()

            # Test component TVL endpoint
            print("5. Testing component TVL endpoint...")
            tvl_params = ComponentTvlParams(
                protocol_system=systems.protocol_systems[0],
                pagination=PaginationParams(page=0, page_size=10),
            )
            tvl = client.get_component_tvl(tvl_params)
            print(f"   Found TVL data for {len(tvl.tvl)} components")
            print(
                f"   Pagination: page {tvl.pagination.page}, size {tvl.pagination.page_size}, total {tvl.pagination.total}"
            )
            if tvl.tvl:
                first_component = list(tvl.tvl.keys())[0]
                print(
                    f"   First component TVL: {first_component} = {tvl.tvl[first_component]}"
                )
            print()

            # Test traced entry points endpoint
            print("6. Testing traced entry points endpoint...")
            entry_points_params = TracedEntryPointParams(
                protocol_system=systems.protocol_systems[0],
                pagination=PaginationParams(page=0, page_size=5),
            )
            entry_points = client.get_traced_entry_points(entry_points_params)
            print(
                f"   Found traced entry points for {len(entry_points.traced_entry_points)} components"
            )
            print(
                f"   Pagination: page {entry_points.pagination.page}, size {entry_points.pagination.page_size}, total {entry_points.pagination.total}"
            )
            print()

        # Test contract state endpoint
        print("7. Testing contract state endpoint...")
        contract_params = ContractStateParams(
            pagination=PaginationParams(page=0, page_size=5)
        )
        contracts = client.get_contract_state(contract_params)
        print(f"   Found {len(contracts.accounts)} contracts")
        print(
            f"   Pagination: page {contracts.pagination.page}, size {contracts.pagination.page_size}, total {contracts.pagination.total}"
        )
        if contracts.accounts:
            print(f"   First contract: {contracts.accounts[0].address.hex()}")
        print()

        # Test protocol state endpoint (if we have a protocol system)
        if systems.protocol_systems:
            print("8. Testing protocol state endpoint...")
            state_params = ProtocolStateParams(
                protocol_system=systems.protocol_systems[0],
                include_balances=True,
                pagination=PaginationParams(page=0, page_size=5),
            )
            states = client.get_protocol_state(state_params)
            print(f"   Found {len(states.states)} protocol states")
            print(
                f"   Pagination: page {states.pagination.page}, size {states.pagination.page_size}, total {states.pagination.total}"
            )
            if states.states:
                print(f"   First state: {states.states[0].component_id}")
            print()

        print("All tests completed successfully!")

    except TychoRPCError as e:
        print(f"RPC Error: {e.message}")
        if e.status_code:
            print(f"Status code: {e.status_code}")
        if e.response_data:
            print(f"Response data: {e.response_data}")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        import traceback

        traceback.print_exc()
        return False

    return True


if __name__ == "__main__":
    success = test_client()
    sys.exit(0 if success else 1)
