from core.encoding.interface import EncodingContext
from core.models.evm.ethereum_token import EthereumToken

from propeller_swap_encoders.curve import CurveSwapStructEncoder

WETH = EthereumToken(
    symbol="WETH",
    address="0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
    decimals=18,
    gas=0,
)
USDT = EthereumToken(
    symbol="USDT", address="0xdAC17F958D2ee523a2206206994597C13D831ec7", decimals=6
)
WBTC = EthereumToken(
    symbol="WBTC", address="0x2260fac5e5542a773aa44fbcfedf7c193bc2c599", decimals=8
)


def test_encode_curve_v2():
    bob = "0x000000000000000000000000000000000000007B"

    swap = {
        "pool_id": "0xD51a44d3FaE010294C616388b506AcdA1bfAAE46",
        "sell_token": USDT,
        "buy_token": WETH,
        "split": 0,
        "sell_amount": 0,
        "buy_amount": 100,
        "token_approval_needed": False,
        "pool_tokens": (USDT, WBTC, WETH),
        "pool_type": "CurveV2PoolState",
        "protocol_specific_attrs": {
            "curve_v2_pool_type": "tricrypto2_non_factory",
            "is_curve_tricrypto": None,
            "quote": None,
            "pool_fee": None,
        },
    }

    curve_encoder = CurveSwapStructEncoder()
    encoded = curve_encoder.encode_swap_struct(
        swap, receiver=bob, encoding_context=EncodingContext()
    )
    assert (
        encoded.hex()
        ==
        # buy token
        "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
        # pool address
        "d51a44d3fae010294c616388b506acda1bfaae46"
        # receiver
        "000000000000000000000000000000000000007b"
        # pool type (tricrypto = 3)
        "03"
        # i (sell token index)
        "00"
        # j (buy token index)
        "02"
        # token_approval_needed
        "00"
    )


def test_encode_curve_v1():
    bob = "0x000000000000000000000000000000000000007B"
    swap = {
        "pool_id": "bebc44782c7db0a1a60cb6fe97d0b483032ff1c7",
        "sell_token": USDT,
        "buy_token": WETH,
        "split": 0,
        "sell_amount": 0,
        "buy_amount": 100,
        "token_approval_needed": False,
        "pool_tokens": (USDT, WBTC, WETH),
        "pool_type": "CurveV1PoolState",
        "protocol_specific_attrs": {
            "curve_v2_pool_type": None,
            "is_curve_tricrypto": None,
            "quote": None,
            "pool_fee": 1000000,
        },
    }
    curve_encoder = CurveSwapStructEncoder()
    encoded = curve_encoder.encode_swap_struct(
        swap, receiver=bob, encoding_context=EncodingContext()
    )
    assert (
        encoded.hex()
        ==
        # buy token
        "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
        # pool address
        "bebc44782c7db0a1a60cb6fe97d0b483032ff1c7"
        # receiver
        "000000000000000000000000000000000000007b"
        # pool type (simple_no_amount = 1)
        "01"
        # i (sell token index)
        "00"
        # j (buy token index)
        "02"
        # token_approval_needed
        "00"
    )


def test_encode_curve_evm_crypto_pool():
    bob = "0x000000000000000000000000000000000000007B"
    swap = {
        "pool_id": "bebc44782c7db0a1a60cb6fe97d0b483032ff1c7",
        "sell_token": USDT,
        "buy_token": WETH,
        "split": 0,
        "sell_amount": 0,
        "buy_amount": 100,
        "token_approval_needed": False,
        "pool_tokens": (USDT, WBTC, WETH),
        "pool_type": "CurveSimulatedPoolState",
        "protocol_specific_attrs": {
            "curve_v2_pool_type": None,
            "is_curve_tricrypto": True,
            "quote": None,
            "pool_fee": None,
        },
    }
    curve_encoder = CurveSwapStructEncoder()
    encoded = curve_encoder.encode_swap_struct(
        swap, receiver=bob, encoding_context=EncodingContext()
    )
    assert (
        encoded.hex()
        ==
        # buy token
        "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
        # pool address
        "bebc44782c7db0a1a60cb6fe97d0b483032ff1c7"
        # receiver
        "000000000000000000000000000000000000007b"
        # pool type (tricrypto = 3)
        "03"
        # i (sell token index)
        "00"
        # j (buy token index)
        "02"
        # token_approval_needed
        "00"
    )
