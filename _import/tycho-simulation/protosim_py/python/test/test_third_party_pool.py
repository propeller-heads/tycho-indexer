import json
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch, call
from venv import create

import pytest
from hexbytes import HexBytes

from tycho_indexer_client.dto import ChangeType

from protosim_py.evm import AccountInfo, AccountUpdate, BlockHeader
from protosim_py.evm.adapter_contract import AdapterContract
from protosim_py.evm.pool_state import ThirdPartyPool
from protosim_py.evm.storage import TychoDBSingleton
from protosim_py.evm.utils import parse_account_info, create_engine
from protosim_py.exceptions import RecoverableSimulationException
from protosim_py.models import EVMBlock, Capability, EthereumToken, Blockchain

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
        "sfrxETH": EthereumToken(
            symbol="sfrxETH",
            address="0xac3e018457b222d93114458476f3e3416abbe38f",
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


def test_overwrites_mock_erc20(pool_state):
    overwrites = pool_state._get_overwrites(pool_state.tokens[0], pool_state.tokens[1])

    assert overwrites == {
        "0x6b175474e89094c44da98b954eedeac495271d0f": {
            # pool balance, caller balance & allowance
            24060209162895628919861412957428278191632570471602070876674374646072182449944: 178754012737301800000,
            58546993237423525698686728856645416951692145960565761888391937184176623942864: 578960446186580977117854925043439539266349923328202820197287920039565648199,
            110136159478993350616340414857413728709904511599989695046923576775517543504731: 578960446186580977117854925043439539266349923328202820197287920039565648199,
        },
        "0xba100000625a3754423978a60c9317c58a424e3d": {
            # pool balance
            24060209162895628919861412957428278191632570471602070876674374646072182449944: 91082987763369890000
        },
    }


def test_overwrites_custom_erc20(asset_dir):
    dai, sfrxEth = Token("DAI"), Token("sfrxETH")
    with open(asset_dir / "sfrxEthToken.evm.runtime", "rb") as fp:
        code = fp.read()
    block = EVMBlock(
        id=18485417,
        hash_="0x28d41d40f2ac275a4f5f621a636b9016b527d11d37d610a45ac3a821346ebf8c",
    )
    engine = create_engine([])
    engine.init_account(
        address=sfrxEth.address,
        account=AccountInfo(
            nonce=0,
            balance=0,
            code=bytearray(code),
        ),
        mocked=True,
        permanent_storage=None,
    )

    pool = ThirdPartyPool(
        block=block,
        id_="0x4626d81b3a1711beb79f4cecff2413886d461677000200000000000000000011",
        tokens=(dai, sfrxEth),
        marginal_prices={
            (sfrxEth, dai): Decimal("7.071503245428245871486924221"),
            (dai, sfrxEth): Decimal("0.1377789143190479049114331557"),
        },
        balances={
            dai.address: "178.7540127373018",
            sfrxEth.address: "91.08298776336989",
        },
        adapter_contract_path=str(asset_dir / "BalancerV2SwapAdapter.evm.runtime"),
        balance_owner="0xBA12222222228d8Ba445958a75a0704d566BF2C8",
        involved_contracts={sfrxEth.address},
    )
    overwrites_zero2one = dict(pool._get_overwrites(pool.tokens[0], pool.tokens[1]))
    overwrites_one2zero = dict(pool._get_overwrites(pool.tokens[1], pool.tokens[0]))

    assert pool.token_storage_slots == {
        "0xac3e018457b222d93114458476f3e3416abbe38f": (3, 4)
    }
    assert overwrites_zero2one == {
        "0x6b175474e89094c44da98b954eedeac495271d0f": {
            # same as test above
            24060209162895628919861412957428278191632570471602070876674374646072182449944: 178754012737301800000,
            58546993237423525698686728856645416951692145960565761888391937184176623942864: 100279494253364362835,
            110136159478993350616340414857413728709904511599989695046923576775517543504731: 100279494253364362835,
        },
        "0xac3e018457b222d93114458476f3e3416abbe38f": {
            # different key compared to our mocked contract in previous test!
            26260780229836133480733911416306220824002130525338603371401637394485347754320: 91082987763369890000
        },
    }
    assert overwrites_one2zero == {
        "0x6b175474e89094c44da98b954eedeac495271d0f": {
            24060209162895628919861412957428278191632570471602070876674374646072182449944: 178754012737301800000,
        },
        "0xac3e018457b222d93114458476f3e3416abbe38f": {
            26260780229836133480733911416306220824002130525338603371401637394485347754320: 91082987763369890000,
            39404303412979837706729056057326168057508607640016353144739821671269873586962: 0,
            55680195869663131363475621218576616366970057593641329011542336081174417563938: 0,
        },
    }
