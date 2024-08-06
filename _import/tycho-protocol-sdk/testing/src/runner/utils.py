from logging import getLogger

from protosim_py.evm.pool_state import ThirdPartyPool
from tycho_client.dto import (
    ResponseProtocolState,
    ProtocolComponent,
    ResponseAccount,
    ComponentWithState,
    Snapshot,
)

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
