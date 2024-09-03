from core.models.evm.ethereum_token import EthereumToken
from propeller_swap_encoders.balancer import BalancerSwapStructEncoder
from core.encoding.interface import EncodingContext


def test_encode_balancer():
    WETH = EthereumToken(
        symbol="WETH",
        address="0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
        decimals=18,
        gas=0,
    )
    DAI = EthereumToken(
        symbol="DAI", address="0x6b175474e89094c44da98b954eedeac495271d0f", decimals=18
    )
    bob = "0x000000000000000000000000000000000000007B"
    swap = {
        "pool_id": "0x06df3b2bbb68adc8b0e302443692037ed9f91b42000000000000000000000063",
        "sell_token": DAI,
        "buy_token": WETH,
        "split": 0,
        "sell_amount": 0,
        "buy_amount": 100,
        "token_approval_needed": False,
        "pool_tokens": (),
        "pool_type": "BalancerStablePoolState",
        "curve_v2_pool_type": None,
        "is_curve_tricrypto": None,
        "quote": None,
        "pool_fee": None,
    }
    balancer_encoder = BalancerSwapStructEncoder()
    encoded = balancer_encoder.encode_swap_struct(
        swap, receiver=bob, encoding_context=EncodingContext(exact_out=False)
    )
    assert (
        encoded.hex()
        ==
        # sell token
        "6b175474e89094c44da98b954eedeac495271d0f"
        # buy token
        "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
        # pool address
        "06df3b2bbb68adc8b0e302443692037ed9f91b42000000000000000000000063"
        # receiver
        "000000000000000000000000000000000000007b"
        # exact_out
        "00"
        # token_approval_needed
        "00"
    )
