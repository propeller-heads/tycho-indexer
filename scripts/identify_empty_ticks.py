import os
import logging as log
from typing import Optional, Any

import requests
import click
from click_params import StringListParamType

log.basicConfig(
    format="{asctime} - {levelname} - {message}",
    style="{",
    datefmt="%Y-%m-%d %H:%M",
    level=log.INFO)

"""
This script identifies protocol components with empty ticks in various exchanges. 
Used to find components that have no net liquidity in their ticks, which can indicate issues with the protocol's state.
"""

class TychoClient:
    """Client for interacting with the Tycho API."""

    def __init__(self, base_url: Optional[str] = None, auth_token: Optional[str] = None):
        self.base_url = base_url or os.getenv("TYCHO_URL", "https://tycho-dev.propellerheads.xyz/v1")
        self.auth_token = auth_token or os.getenv("TYCHO_AUTH_TOKEN", "sampletoken")
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": self.auth_token
        }

    def get_all_protocol_components(self, protocol_system: str, tvl_gt: int) -> list[dict[str, Any]]:
        all_components = []
        page = 0
        page_size = 500
        endpoint = f"{self.base_url}/protocol_components"
        log.info(f"Fetching protocol components from {endpoint}")

        while True:
            payload = {
                "chain": "ethereum",
                "pagination": {
                    "page": page,
                    "page_size": page_size
                },
                "protocol_system": protocol_system,
                "tvl_gt": tvl_gt
            }

            try:
                response = requests.post(endpoint, json=payload, headers=self.headers)
                response.raise_for_status()
                data = response.json()
                results = data.get("protocol_components", [])
                all_components.extend(results)

                if len(results) < page_size:
                    break

                page += 1
            except requests.RequestException as e:
                log.error(f"Error fetching protocol components: {e}")
                raise e

        return all_components

    def get_protocol_states(self, component_ids: list[str], protocol_system: str, page_size: int = 100) -> list[dict[str, Any]]:
        all_results = []
        endpoint = f"{self.base_url}/protocol_state"
        log.info(f"Fetching protocol states from {endpoint}")

        for component_chunk in chunked_list(component_ids, page_size):
            page = 0
            while True:
                payload = {
                    "include_balances": True,
                    "protocol_system": protocol_system,
                    "protocol_ids": [
                        {
                            "chain": "ethereum",
                            "id": cid
                        } for cid in component_chunk
                    ],
                    "pagination": {
                        "page": page,
                        "page_size": page_size
                    }
                }

                try:
                    response = requests.post(endpoint, json=payload, headers=self.headers)
                    response.raise_for_status()
                    data = response.json()
                    states = data.get("states", [])
                    all_results.extend(states)

                    if len(states) < page_size:
                        break

                    page += 1
                except requests.RequestException as e:
                    log.error(f"Error fetching protocol states: {e}")
                    raise e

        return all_results

def chunked_list(lst, n):
    """Splits the input list `lst` into chunks of size `n`."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def hex_to_signed_int(hex_str):
    # Remove '0x' prefix and convert to bytes
    hex_val = hex_str[2:]
    bytes_val = bytes.fromhex(hex_val)
    # Convert bytes to signed integer (big-endian)
    return int.from_bytes(bytes_val, byteorder="big", signed=True)


def has_empty_ticks(attributes: dict[str, str]):
    """
    Checks if a component has empty ticks by summing net liquidity.
    """

    net_liquidity_sum = 0
    for key in attributes:
        if key.startswith("ticks/") and key.endswith("/net-liquidity"):
            hex_str = attributes[key]
            log.debug(f"key: {key}, int: {hex_to_signed_int(hex_str)}")
            net_liquidity_sum += hex_to_signed_int(hex_str)

    return net_liquidity_sum != 0


def identify_empty_ticks(protocol_components: list[dict[str, str]]):
    empty_ticks = []
    for component in protocol_components:
        attributes = component.get("attributes", {})
        if has_empty_ticks(attributes):
            empty_ticks.append(component["component_id"])

    return empty_ticks


@click.command()
@click.option("--tvl_gt", type=int, default=1,)
@click.option("--exchange", type=StringListParamType(','), default="uniswap_v3,uniswap_v4,ekubo_v2,pancakeswap_v3",
              help="Comma-separated list of exchanges to filter by")
def main(tvl_gt, exchange: list[str]):
    """Identify protocol components with empty ticks for specified exchanges."""

    client = TychoClient()
    for protocol_system in exchange:
        try:
            log.info(f"Fetching components for {protocol_system}")
            protocol_components = client.get_all_protocol_components(protocol_system, tvl_gt)
            log.info(f"Found {len(protocol_components)} protocol components")

            component_ids = [c["id"] for c in protocol_components]
            log.info(f"Fetching protocol systems for {len(component_ids)} components")
            protocol_states = client.get_protocol_states(component_ids, protocol_system)
        except requests.RequestException as e:
            log.error(f"Failed to fetch data for {protocol_system}: {e}")
            continue

        log.info(f"Fetched {len(protocol_states)} protocol systems")
        empty_tick_components = identify_empty_ticks(protocol_states)

        log.info(f"Identified {len(empty_tick_components)} components with empty ticks:")
        for protocol in empty_tick_components:
            log.info(protocol)


if __name__ == "__main__":
    main()
