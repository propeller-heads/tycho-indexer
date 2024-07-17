import logging
import time
from decimal import Decimal
from fractions import Fraction
from typing import Any, Union, NamedTuple

import eth_abi
from eth_abi.exceptions import DecodingError
from eth_typing import HexStr
from eth_utils import keccak
from eth_utils.abi import collapse_if_tuple
from hexbytes import HexBytes
from protosim_py import (
    SimulationEngine,
    SimulationParameters,
    SimulationResult,
    StateUpdate,
)

from .constants import EXTERNAL_ACCOUNT
from .models import Address, EthereumToken, EVMBlock, Capability
from .utils import load_abi, maybe_coerce_error

log = logging.getLogger(__name__)

TStateOverwrites = dict[Address, dict[int, int]]


class Trade(NamedTuple):
    """
    Trade represents a simple trading operation with fields:
        received_amount: Amount received from the trade
        gas_used: Amount of gas used in the transaction
        price: Price at which the trade was executed
    """

    received_amount: float
    gas_used: float
    price: float


class ProtoSimResponse:
    def __init__(self, return_value: Any, simulation_result: "SimulationResult"):
        self.return_value = return_value
        self.simulation_result = simulation_result


class ProtoSimContract:
    def __init__(self, address: Address, abi_name: str, engine: SimulationEngine):
        self.abi = load_abi(abi_name)
        self.address = address
        self.engine = engine
        self._default_tx_env = dict(
            caller=EXTERNAL_ACCOUNT, to=self.address, value=0, overrides={}
        )
        functions = [f for f in self.abi if f["type"] == "function"]
        self._functions = {f["name"]: f for f in functions}
        if len(self._functions) != len(functions):
            raise ValueError(
                f"ProtoSimContract does not support overloaded function names! "
                f"Encountered while loading {abi_name}."
            )

    def _encode_input(self, fname: str, args: list) -> bytearray:
        func = self._functions[fname]
        types = [collapse_if_tuple(t) for t in func["inputs"]]
        selector = keccak(text=f"{fname}({','.join(types)})")[:4]
        return bytearray(selector + eth_abi.encode(types, args))

    def _decode_output(self, fname: str, encoded: list[int]) -> Any:
        func = self._functions[fname]
        types = [collapse_if_tuple(t) for t in func["outputs"]]
        return eth_abi.decode(types, bytearray(encoded))

    def call(
        self,
        fname: str,
        *args: list[Union[int, str, bool, bytes]],
        block_number,
        timestamp: int = None,
        overrides: TStateOverwrites = None,
        caller: Address = EXTERNAL_ACCOUNT,
        value: int = 0,
    ) -> ProtoSimResponse:
        call_data = self._encode_input(fname, *args)
        params = SimulationParameters(
            data=call_data,
            to=self.address,
            block_number=block_number,
            timestamp=timestamp or int(time.time()),
            overrides=overrides or {},
            caller=caller,
            value=value,
        )
        sim_result = self._simulate(params)
        try:
            output = self._decode_output(fname, sim_result.result)
        except DecodingError:
            log.warning("Failed to decode output")
            output = None
        return ProtoSimResponse(output, sim_result)

    def _simulate(self, params: SimulationParameters) -> "SimulationResult":
        """Run simulation and handle errors.

        It catches a RuntimeError:

        - if it's ``Execution reverted``, re-raises a RuntimeError
          with a Tenderly link added
        - if it's ``Out of gas``, re-raises a RecoverableSimulationException
        - otherwise it just re-raises the original error.
        """
        try:
            simulation_result = self.engine.run_sim(params)
            return simulation_result
        except RuntimeError as err:
            try:
                coerced_err = maybe_coerce_error(err, self, params.gas_limit)
            except Exception:
                log.exception("Couldn't coerce error. Re-raising the original one.")
                raise err
            msg = str(coerced_err)
            if "Revert!" in msg:
                raise type(coerced_err)(msg, repr(self)) from err
            else:
                raise coerced_err


class AdapterContract(ProtoSimContract):
    """
    The AdapterContract provides an interface to interact with the protocols implemented
    by third parties using the `propeller-protocol-lib`.
    """

    def __init__(self, address: Address, engine: SimulationEngine):
        super().__init__(address, "ISwapAdapter", engine)

    def price(
        self,
        pair_id: HexStr,
        sell_token: EthereumToken,
        buy_token: EthereumToken,
        amounts: list[int],
        block: EVMBlock,
        overwrites: TStateOverwrites = None,
    ) -> list[Fraction]:
        args = [HexBytes(pair_id), sell_token.address, buy_token.address, amounts]
        res = self.call(
            "price",
            args,
            block_number=block.id,
            timestamp=int(block.ts.timestamp()),
            overrides=overwrites,
        )
        return list(map(lambda x: Fraction(*x), res.return_value[0]))

    def swap(
        self,
        pair_id: HexStr,
        sell_token: EthereumToken,
        buy_token: EthereumToken,
        is_buy: bool,
        amount: Decimal,
        block: EVMBlock,
        overwrites: TStateOverwrites = None,
    ) -> tuple[Trade, dict[str, StateUpdate]]:
        args = [
            HexBytes(pair_id),
            sell_token.address,
            buy_token.address,
            int(is_buy),
            amount,
        ]
        res = self.call(
            "swap",
            args,
            block_number=block.id,
            timestamp=int(block.ts.timestamp()),
            overrides=overwrites,
        )
        amount, gas, price = res.return_value[0]
        return Trade(amount, gas, Fraction(*price)), res.simulation_result.state_updates

    def get_limits(
        self,
        pair_id: HexStr,
        sell_token: EthereumToken,
        buy_token: EthereumToken,
        block: EVMBlock,
        overwrites: TStateOverwrites = None,
    ) -> tuple[int, int]:
        args = [HexBytes(pair_id), sell_token.address, buy_token.address]
        res = self.call(
            "getLimits",
            args,
            block_number=block.id,
            timestamp=int(block.ts.timestamp()),
            overrides=overwrites,
        )
        return res.return_value[0]

    def get_capabilities(
        self, pair_id: HexStr, sell_token: EthereumToken, buy_token: EthereumToken
    ) -> set[Capability]:
        args = [HexBytes(pair_id), sell_token.address, buy_token.address]
        res = self.call("getCapabilities", args, block_number=1)
        return set(map(Capability, res.return_value[0]))

    def min_gas_usage(self) -> int:
        res = self.call("minGasUsage", [], block_number=1)
        return res.return_value[0]
