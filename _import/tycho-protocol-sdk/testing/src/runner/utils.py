from logging import getLogger
from typing import Union

from protosim_py.evm.pool_state import ThirdPartyPool
from protosim_py.models import EthereumToken
from tycho_client.dto import (
    ResponseProtocolState,
    ProtocolComponent,
    ResponseAccount,
    ComponentWithState,
    Snapshot,
    HexBytes,
    TokensParams,
    PaginationParams,
    ResponseToken,
)
from tycho_client.rpc_client import TychoRPCClient

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
            log.warning(f"State for pool {pool_id} not found in components")
            continue
        states[pool_id]["state"] = state

    states = {id_: ComponentWithState(**state) for id_, state in states.items()}
    return Snapshot(states=states, vm_storage=vm_storage)


def token_factory(rpc_client: TychoRPCClient) -> callable(HexBytes):
    _client = rpc_client
    _token_cache: dict[HexBytes, EthereumToken] = {}

    def factory(addresses: Union[HexBytes, list[HexBytes]]) -> list[EthereumToken]:
        if not isinstance(addresses, list):
            addresses = [addresses]

        response = dict()
        to_fetch = []

        for address in addresses:
            if address in _token_cache:
                response[address] = _token_cache[address]
            else:
                to_fetch.append(address)

        if to_fetch:
            pagination = PaginationParams(page_size=len(to_fetch), page=0)
            params = TokensParams(token_addresses=to_fetch, pagination=pagination)
            tokens = _client.get_tokens(params)
            for token in tokens:
                eth_token = EthereumToken(**token.dict())

                response[token.address] = eth_token
                _token_cache[token.address] = eth_token

        return [response[address] for address in addresses]

    return factory
