from typing import Any

from core.encoding.interface import SwapStructEncoder, EncodingContext
from core.type_aliases import Address
from eth_abi.packed import encode_abi_packed
from hexbytes import HexBytes


class BalancerSwapStructEncoder(SwapStructEncoder):
    def encode_swap_struct(
        self, swap: dict[str, Any], receiver: Address, encoding_context: EncodingContext
    ) -> bytes:
        return encode_abi_packed(
            ["address", "address", "bytes32", "address", "bool", "bool"],
            [
                swap["sell_token"].address,
                swap["buy_token"].address,
                HexBytes(swap["pool_id"]),
                receiver,
                encoding_context.exact_out,
                swap["token_approval_needed"],
            ],
        )
