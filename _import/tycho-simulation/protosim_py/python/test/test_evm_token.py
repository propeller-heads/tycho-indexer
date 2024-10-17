import os

import pytest

from protosim_py.evm.storage import TychoDBSingleton
from protosim_py.evm.token import brute_force_slots
from protosim_py.evm.utils import (
    create_engine,
)
from test.evm.utils import init_contract_via_rpc
from protosim_py.models import EthereumToken, EVMBlock

_ETH_RPC_URL = os.getenv("ETH_RPC_URL")


@pytest.mark.skipif(
    _ETH_RPC_URL is None,
    reason="Geth RPC access required. Please via `ETH_RPC_URL` env variable.",
)
def test_brute_force_slots():
    block = EVMBlock(
        20984206, "0x01a709ad31a9ff223f7932ae8f6d6762e02b114250393adf128a2858b39c4b9d"
    )
    token_address = "0xac3E018457B222d93114458476f3E3416Abbe38F"
    token = EthereumToken("sFRAX", token_address, 18)
    TychoDBSingleton.initialize()
    engine = create_engine([], trace=True)
    engine = init_contract_via_rpc(block, token_address, engine, _ETH_RPC_URL)

    balance_slots, allowance_slot = brute_force_slots(token, block, engine)

    assert balance_slots == 3
    assert allowance_slot == 4
