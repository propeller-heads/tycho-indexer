import json
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch, call

import pytest
from hexbytes import HexBytes
from protosim_py._protosim_py import AccountInfo

from protosim_py.evm import BlockHeader
from protosim_py.evm.adapter_contract import AdapterContract
from protosim_py.evm.pool_state import ThirdPartyPool
from protosim_py.evm.storage import TychoDBSingleton
from protosim_py.evm.utils import parse_account_info, create_engine
from protosim_py.exceptions import RecoverableSimulationException
from protosim_py.models import EVMBlock, Capability, EthereumToken

ADDRESS_ZERO = "0x0000000000000000000000000000000000000000"


# noinspection PyPep8Naming
def Token(name: str) -> EthereumToken:
    return {
        "DAI": EthereumToken(
            symbol="DAI",
            address="0x6B175474E89094C44Da98b954EedeAC495271d0F",
            decimals=18,
        ),
        "BAL": EthereumToken(
            symbol="BAL",
            address="0xba100000625a3754423978a60c9317c58a424e3D",
            decimals=18,
        ),
    }[name]


@pytest.fixture()
def adapter_contract_path(asset_dir) -> Path:
    return Path(__file__).parent / "assets" / "BalancerV2SwapAdapter.evm.runtime"


@pytest.fixture(autouse=True, scope="module")
def setup_db(asset_dir):
    with open(asset_dir / "balancer_contract_storage.json") as fp:
        data = json.load(fp)

    accounts = parse_account_info(data["accounts"])

    TychoDBSingleton.initialize()
    db = TychoDBSingleton.get_instance()
    block = BlockHeader(
        20463609,
        "0x4315fd1afc25cc2ebc72029c543293f9fd833eeb305e2e30159459c827733b1b",
        1722875891,
    )
    engine = create_engine([], False)
    for account in accounts:
        engine.init_account(
            address=account.address,
            account=AccountInfo(balance=account.balance, nonce=0, code=account.code),
            mocked=False,
            permanent_storage=None,
        )
    db.update(accounts, block)


def test_encode_input():
    adapter = AdapterContract(ADDRESS_ZERO, None)
    exp = (
        "0x48bd7dfd616100000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000"
    )

    res = HexBytes(
        adapter._encode_input("getCapabilities", [b"aa", ADDRESS_ZERO, ADDRESS_ZERO])
    ).hex()

    assert res == exp


def test_init(asset_dir):
    dai, bal = Token("DAI"), Token("BAL")
    block = EVMBlock(
        id=18485417,
        hash_="0x28d41d40f2ac275a4f5f621a636b9016b527d11d37d610a45ac3a821346ebf8c",
    )
    pool = ThirdPartyPool(
        block=block,
        id_="0x4626d81b3a1711beb79f4cecff2413886d461677000200000000000000000011",
        tokens=(dai, bal),
        marginal_prices={},
        balances={dai.address: "178.7540127373018", bal.address: "91.08298776336989"},
        adapter_contract_path=str(asset_dir / "BalancerV2SwapAdapter.evm.runtime"),
    )

    assert pool.capabilities == {
        Capability.SellSide,
        Capability.BuySide,
        Capability.PriceFunction,
        Capability.HardLimits,
    }
    assert pool.marginal_prices == {
        (bal, dai): Decimal("7.071503245428245871486924221"),
        (dai, bal): Decimal("0.1377789143190479049114331557"),
    }


@pytest.fixture(scope="module")
def pool_state(asset_dir):
    dai, bal = Token("DAI"), Token("BAL")
    block = EVMBlock(
        id=18485417,
        hash_="0x28d41d40f2ac275a4f5f621a636b9016b527d11d37d610a45ac3a821346ebf8c",
    )
    pool = ThirdPartyPool(
        block=block,
        id_="0x4626d81b3a1711beb79f4cecff2413886d461677000200000000000000000011",
        tokens=(dai, bal),
        marginal_prices={
            (bal, dai): Decimal("7.071503245428245871486924221"),
            (dai, bal): Decimal("0.1377789143190479049114331557"),
        },
        balances={dai.address: "178.7540127373018", bal.address: "91.08298776336989"},
        adapter_contract_path=str(asset_dir / "BalancerV2SwapAdapter.evm.runtime"),
        balance_owner="0xBA12222222228d8Ba445958a75a0704d566BF2C8",
    )
    return pool


def test_sell_amount_limit(pool_state):
    dai, bal = Token("DAI"), Token("BAL")

    dai_limit = pool_state.get_sell_amount_limit(dai, bal)
    bal_limit = pool_state.get_sell_amount_limit(bal, dai)

    assert dai_limit == Decimal("100.279494253364362835")
    assert bal_limit == Decimal("13.997408640689987484")


def test_get_amount_out(pool_state):
    t0, t1 = pool_state.tokens

    buy_amount, gas, new_state = pool_state.get_amount_out(t1, Decimal(10), t0)

    assert buy_amount == Decimal("58.510230650511937163")
    # TODO: if run in isolation, gas is higher here - unsure yet why we'll
    #  probably need trace to debug this, running only test_sell_amount_limit
    #  before reduces gas already, running test_init does not.
    assert gas == 85995
    assert new_state.marginal_prices != pool_state.marginal_prices
    for override in new_state.block_lasting_overwrites.values():
        assert isinstance(override, dict)


def test_sequential_get_amount_outs(pool_state):
    t0, t1 = pool_state.tokens

    _, _, new_state = pool_state.get_amount_out(t1, Decimal(10), t0)
    buy_amount, gas, new_state2 = new_state.get_amount_out(t1, Decimal(10), t0)

    assert buy_amount == Decimal("41.016419447002364763")
    assert new_state2.marginal_prices != new_state.marginal_prices


def test_get_amount_out_dust(pool_state):
    t0, t1 = pool_state.tokens

    buy_amount, gas, new_state = pool_state.get_amount_out(
        t1, Decimal(0.0000000000001), t0
    )

    assert buy_amount == Decimal("0")
    assert new_state.marginal_prices == pool_state.marginal_prices


def test_get_amount_out_sell_limit(pool_state):
    t0, t1 = pool_state.tokens

    with pytest.raises(RecoverableSimulationException) as e:
        pool_state.get_amount_out(t1, Decimal(100), t0)

    # check the partial trade sells the max sell limit
    assert e.value.partial_trade[3] == Decimal("13.997408640689987484")


def test_stateless_contract_pool(asset_dir):
    with patch("protosim_py.evm.pool_state.get_code_for_address") as mock_get_code:
        mock_get_code.return_value = bytes.fromhex("363d")

        dai, bal = Token("DAI"), Token("BAL")
        block = EVMBlock(
            id=18485417,
            hash_="0x28d41d40f2ac275a4f5f621a636b9016b527d11d37d610a45ac3a821346ebf8c",
        )
        pool = ThirdPartyPool(
            block=block,
            id_="0x4626d81b3a1711beb79f4cecff2413886d461677000200000000000000000011",
            tokens=(dai, bal),
            marginal_prices={
                (bal, dai): Decimal("7.071503245428245871486924221"),
                (dai, bal): Decimal("0.1377789143190479049114331557"),
            },
            balances={
                dai.address: "178.7540127373018",
                bal.address: "91.08298776336989",
            },
            adapter_contract_path=str(asset_dir / "BalancerV2SwapAdapter.evm.runtime"),
            balance_owner="0xBA12222222228d8Ba445958a75a0704d566BF2C8",
            stateless_contracts={
                "call:0xba12222222228d8ba445958a75a0704d566bf2c8:getAuthorizer()": None,
                "0x9008D19f58AAbD9eD0D60971565AA8510560ab41": None,
            },
        )

        mock_get_code.assert_has_calls(
            [
                call("0x9008D19f58AAbD9eD0D60971565AA8510560ab41"),
                call("0xa331d84ec860bf466b4cdccfb4ac09a1b43f3ae6"),
            ],
            any_order=True,
        )

        assert mock_get_code.call_count == 2
