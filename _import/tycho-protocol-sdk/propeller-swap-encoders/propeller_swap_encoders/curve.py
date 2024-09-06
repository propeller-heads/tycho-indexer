import enum
from typing import Any

from core.encoding.interface import EncodingContext, SwapStructEncoder
from core.type_aliases import Address
from eth_abi.packed import encode_abi_packed
from eth_utils import to_checksum_address

curve_config = {
    # curve pool type 4
    "eth_stable_pools": [
        "0xA96A65c051bF88B4095Ee1f2451C2A9d43F53Ae2",
        "0xF9440930043eb3997fc70e1339dBb11F341de7A8",
        "0xa1F8A6807c402E4A15ef4EBa36528A3FED24E577",
        "0xBfAb6FA95E0091ed66058ad493189D2cB29385E6",
        "0x94B17476A93b3262d87B9a326965D1E91f9c13E7",
    ],
    # curve pool type 7
    "v2_eth_pools": [
        "0x9409280DC1e6D33AB7A8C6EC03e5763FB61772B5",
        "0x5FAE7E604FC3e24fd43A72867ceBaC94c65b404A",
        "0x0f3159811670c117c372428D4E69AC32325e4D0F",
        "0x838af967537350D2C44ABB8c010E49E32673ab94",
        "0xC26b89A667578ec7b3f11b2F98d6Fd15C07C54ba",
        "0x6bfE880Ed1d639bF80167b93cc9c56a39C1Ba2dC",
        "0x0E9B5B092caD6F1c5E6bc7f89Ffe1abb5c95F1C2",
        "0x21410232B484136404911780bC32756D5d1a9Fa9",
        "0xfB8814D005C5f32874391e888da6eB2fE7a27902",
        "0xe0e970a99bc4F53804D8145beBBc7eBc9422Ba7F",
        "0x6e314039f4C56000F4ebb3a7854A84cC6225Fb92",
        "0xf861483fa7E511fbc37487D91B6FAa803aF5d37c",
    ],
}


class CurvePoolType(enum.IntEnum):
    """
    Represents different swap logics of curve pools. For more details, please see
    CurveSwapMethodV1 in defibot-contracts repository.
    """

    simple = 0
    simple_no_amount = 1
    tricrypto = 3
    eth_stableswap = 4
    underlying = 5
    underlying_no_amount = 6
    crypto_v2 = 7
    crypto_v2_2_tokens_not_factory = 8


curve_v2_pool_type_mapping: dict[str, CurvePoolType] = {
    "tricrypto2_non_factory": CurvePoolType.tricrypto,
    "two_token_factory": CurvePoolType.crypto_v2,
    "two_token_non_factory": CurvePoolType.crypto_v2_2_tokens_not_factory,
}


class CurveSwapStructEncoder(SwapStructEncoder):
    eth_stable_pools: list[str] = curve_config["eth_stable_pools"]
    v2_eth_pools = curve_config["v2_eth_pools"]

    def encode_swap_struct(
        self, swap: dict[str, Any], receiver: Address, encoding_context: EncodingContext
    ) -> bytes:

        pool_type = swap["pool_type"]
        if pool_type == "CurveSimulatedPoolState":
            curve_pool_type = (
                CurvePoolType.tricrypto
                if swap["protocol_specific_attrs"]["is_curve_tricrypto"]
                else CurvePoolType.simple_no_amount
            )
        elif to_checksum_address(swap["pool_id"]) in self.v2_eth_pools:
            curve_pool_type = CurvePoolType.crypto_v2
        elif to_checksum_address(swap["pool_id"]) in self.eth_stable_pools:
            curve_pool_type = CurvePoolType.eth_stableswap
        else:
            curve_pool_type = (
                curve_v2_pool_type_mapping[
                    swap["protocol_specific_attrs"]["curve_v2_pool_type"]
                ]
                if pool_type == "CurveV2PoolState"
                else CurvePoolType.simple_no_amount
            )

        return encode_abi_packed(
            ["address", "address", "address", "uint8", "uint8", "uint8", "bool"],
            [
                swap["buy_token"].address,
                swap["pool_id"],
                receiver,
                curve_pool_type,
                swap["pool_tokens"].index(swap["sell_token"]),
                swap["pool_tokens"].index(swap["buy_token"]),
                swap["token_approval_needed"],
            ],
        )
