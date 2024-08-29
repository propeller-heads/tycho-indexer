from typing import Any

from core.encoding.interface import SwapStructEncoder
from core.type_aliases import Address
from eth_abi.packed import encode_abi_packed
from hexbytes import HexBytes


class BalancerSwapStructEncoder(SwapStructEncoder):
    def encode_swap_struct(
        self, swap: dict[str, Any], receiver: Address, exact_out: bool, **kwargs
    ) -> bytes:
        """
        Parameters:
        ----------
        swap
            The swap to encode
        receiver
            The receiver of the buy token
        exact_out
            Whether the amount encoded is the exact amount out
        """
        return encode_abi_packed(
            ["address", "address", "bytes32", "address", "bool", "bool"],
            [
                swap["sell_token"].address,
                swap["buy_token"].address,
                HexBytes(swap["pool_id"]),
                receiver,
                exact_out,
                swap["token_approval_needed"],
            ],
        )
