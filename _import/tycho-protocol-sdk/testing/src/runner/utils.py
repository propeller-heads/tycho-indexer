from logging import getLogger
from typing import Union

from eth_utils import to_checksum_address
from tycho_simulation_py.models import EthereumToken
from tycho_indexer_client.dto import (
    ResponseProtocolState,
    ProtocolComponent,
    ResponseAccount,
    ComponentWithState,
    Snapshot,
    HexBytes,
    TokensParams,
    PaginationParams,
)
from tycho_indexer_client.rpc_client import TychoRPCClient

log = getLogger(__name__)


def build_snapshot_message(
    protocol_states: list[ResponseProtocolState],
    protocol_components: list[ProtocolComponent],
    account_states: list[ResponseAccount],
) -> Snapshot:
    vm_storage = {state.address: state for state in account_states}

    states = {}
    for component in protocol_components:
        pool_id = component.id
        states[pool_id] = {"component": component}
    for state in protocol_states:
        pool_id = state.component_id
        if pool_id not in states:
            continue
        states[pool_id]["state"] = state

    states = {id_: ComponentWithState(**state) for id_, state in states.items()}
    return Snapshot(states=states, vm_storage=vm_storage)


def token_factory(rpc_client: TychoRPCClient) -> callable(HexBytes):
    _client = rpc_client
    _token_cache: dict[str, EthereumToken] = {}

    def factory(requested_addresses: Union[str, list[str]]) -> list[EthereumToken]:
        if not isinstance(requested_addresses, list):
            requested_addresses = [to_checksum_address(requested_addresses)]
        else:
            requested_addresses = [to_checksum_address(a) for a in requested_addresses]

        response = dict()
        to_fetch = []

        for address in requested_addresses:
            if address in _token_cache:
                response[address] = _token_cache[address]
            else:
                to_fetch.append(address)

        if to_fetch:
            pagination = PaginationParams(page_size=len(to_fetch), page=0)
            params = TokensParams(token_addresses=to_fetch, pagination=pagination)
            tokens = _client.get_tokens(params).tokens
            for token in tokens:
                address = to_checksum_address(token.address)
                eth_token = EthereumToken(
                    symbol=token.symbol,
                    address=address,
                    decimals=token.decimals,
                    gas=token.gas,
                )

                response[address] = eth_token
                _token_cache[address] = eth_token

        return [response[address] for address in requested_addresses]

    return factory
