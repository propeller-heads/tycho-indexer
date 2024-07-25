import json
import os
from decimal import Decimal
from fractions import Fraction
from functools import lru_cache
from logging import getLogger
from pathlib import Path
from typing import Final, Any

import eth_abi
from eth_typing import HexStr
from hexbytes import HexBytes
from protosim_py import SimulationEngine, AccountInfo
import requests
from web3 import Web3

from .constants import EXTERNAL_ACCOUNT, MAX_BALANCE, ASSETS_FOLDER
from .exceptions import OutOfGas
from .models import Address, EthereumToken
from .tycho_db import TychoDBSingleton

log = getLogger(__name__)


def decode_tycho_exchange(exchange: str) -> (str, bool):
    # removes vm prefix if present, returns True if vm prefix was present (vm protocol) or False if native protocol
    return (exchange.split(":")[1], False) if "vm:" in exchange else (exchange, True)


def create_engine(
    mocked_tokens: list[Address], trace: bool = False
) -> SimulationEngine:
    """Create a simulation engine with a mocked ERC20 contract at given addresses.

    Parameters
    ----------
    mocked_tokens
        A list of addresses at which a mocked ERC20 contract should be inserted.

    trace
        Whether to trace calls, only meant for debugging purposes, might print a lot of
        data to stdout.
    """

    db = TychoDBSingleton.get_instance()
    engine = SimulationEngine.new_with_tycho_db(db=db, trace=trace)

    for t in mocked_tokens:
        info = AccountInfo(
            balance=0, nonce=0, code=get_contract_bytecode(ASSETS_FOLDER / "ERC20.bin")
        )
        engine.init_account(
            address=t, account=info, mocked=True, permanent_storage=None
        )
    engine.init_account(
        address=EXTERNAL_ACCOUNT,
        account=AccountInfo(balance=MAX_BALANCE, nonce=0, code=None),
        mocked=False,
        permanent_storage=None,
    )

    return engine


class ERC20OverwriteFactory:
    def __init__(self, token: EthereumToken):
        """
        Initialize the ERC20OverwriteFactory.

        Parameters:
            token: The token object.
        """
        self._token = token
        self._overwrites = dict()
        self._balance_slot: Final[int] = 0
        self._allowance_slot: Final[int] = 1

    def set_balance(self, balance: int, owner: Address):
        """
        Set the balance for a given owner.

        Parameters:
            balance: The balance value.
            owner: The owner's address.
        """
        storage_index = get_storage_slot_at_key(HexStr(owner), self._balance_slot)
        self._overwrites[storage_index] = balance
        log.log(
            5,
            f"Override balance: token={self._token.address} owner={owner}"
            f"value={balance} slot={storage_index}",
        )

    def set_allowance(self, allowance: int, spender: Address, owner: Address):
        """
        Set the allowance for a given spender and owner.

        Parameters:
            allowance: The allowance value.
            spender: The spender's address.
            owner: The owner's address.
        """
        storage_index = get_storage_slot_at_key(
            HexStr(spender),
            get_storage_slot_at_key(HexStr(owner), self._allowance_slot),
        )
        self._overwrites[storage_index] = allowance
        log.log(
            5,
            f"Override allowance: token={self._token.address} owner={owner}"
            f"spender={spender} value={allowance} slot={storage_index}",
        )

    def get_protosim_overwrites(self) -> dict[Address, dict[int, int]]:
        """
        Get the overwrites dictionary of previously collected values.

        Returns:
            dict[Address, dict]: A dictionary containing the token's address
            and the overwrites.
        """
        # Protosim returns lowercase addresses in state updates returned from simulation

        return {self._token.address.lower(): self._overwrites}

    def get_geth_overwrites(self) -> dict[Address, dict[int, int]]:
        """
        Get the overwrites dictionary of previously collected values.

        Returns:
            dict[Address, dict]: A dictionary containing the token's address
            and the overwrites.
        """
        formatted_overwrites = {
            HexBytes(key).hex(): "0x" + HexBytes(val).hex().lstrip("0x").zfill(64)
            for key, val in self._overwrites.items()
        }

        code = "0x" + get_contract_bytecode(ASSETS_FOLDER / "ERC20.bin").hex()
        return {self._token.address: {"stateDiff": formatted_overwrites, "code": code}}


def get_storage_slot_at_key(key: Address, mapping_slot: int) -> int:
    """Get storage slot index of a value stored at a certain key in a mapping

    Parameters
    ----------
    key
        Key in a mapping. This function is meant to work with ethereum addresses
        and accepts only strings.
    mapping_slot
        Storage slot at which the mapping itself is stored. See the examples for more
        explanation.

    Returns
    -------
    slot
        An index of a storage slot where the value at the given key is stored.

    Examples
    --------
    If a mapping is declared as a first variable in solidity code, its storage slot
    is 0 (e.g. ``balances`` in our mocked ERC20 contract). Here's how to compute
    a storage slot where balance of a given account is stored::

        get_storage_slot_at_key("0xC63135E4bF73F637AF616DFd64cf701866BB2628", 0)

    For nested mappings, we need to apply the function twice. An example of this is
    ``allowances`` in ERC20. It is a mapping of form:
    ``dict[owner, dict[spender, value]]``. In our mocked ERC20 contract, ``allowances``
    is a second variable, so it is stored at slot 1. Here's how to get a storage slot
    where an allowance of ``0xspender`` to spend ``0xowner``'s money is stored::

        get_storage_slot_at_key("0xspender", get_storage_slot_at_key("0xowner", 1)))

    See Also
    --------
    `Solidity Storage Layout documentation
    <https://docs.soliditylang.org/en/v0.8.13/internals/layout_in_storage.html#mappings-and-dynamic-arrays>`_
    """
    key_bytes = bytes.fromhex(key[2:]).rjust(32, b"\0")
    mapping_slot_bytes = int.to_bytes(mapping_slot, 32, "big")
    slot_bytes = Web3.keccak(key_bytes + mapping_slot_bytes)
    return int.from_bytes(slot_bytes, "big")


@lru_cache
def get_contract_bytecode(path: str) -> bytes:
    """Load contract bytecode from a file given an absolute path"""
    with open(path, "rb") as fh:
        code = fh.read()
    return code


def frac_to_decimal(frac: Fraction) -> Decimal:
    return Decimal(frac.numerator) / Decimal(frac.denominator)


def load_abi(name_or_path: str) -> dict:
    if os.path.exists(abspath := os.path.abspath(name_or_path)):
        path = abspath
    else:
        path = f"{os.path.dirname(os.path.abspath(__file__))}/assets/{name_or_path}.abi"
    try:
        with open(os.path.abspath(path)) as f:
            abi: dict = json.load(f)
    except FileNotFoundError:
        search_dir = f"{os.path.dirname(os.path.abspath(__file__))}/assets/"

        # List all files in search dir and subdirs suggest them to the user in an error message
        available_files = []
        for dirpath, dirnames, filenames in os.walk(search_dir):
            for filename in filenames:
                # Make paths relative to search_dir
                relative_path = os.path.relpath(
                    os.path.join(dirpath, filename), search_dir
                )
                available_files.append(relative_path.replace(".abi", ""))

        raise FileNotFoundError(
            f"File {name_or_path} not found. "
            f"Did you mean one of these? {', '.join(available_files)}"
        )
    return abi


# https://docs.soliditylang.org/en/latest/control-structures.html#panic-via-assert-and-error-via-require
solidity_panic_codes = {
    0: "GenericCompilerPanic",
    1: "AssertionError",
    17: "ArithmeticOver/Underflow",
    18: "ZeroDivisionError",
    33: "UnkownEnumMember",
    34: "BadStorageByteArrayEncoding",
    51: "EmptyArray",
    0x32: "OutOfBounds",
    0x41: "OutOfMemory",
    0x51: "BadFunctionPointer",
}


def parse_solidity_error_message(data) -> str:
    data_bytes = HexBytes(data)
    error_string = f"Failed to decode: {data}"
    # data is encoded as Error(string)
    if data_bytes[:4] == HexBytes("0x08c379a0"):
        (error_string,) = eth_abi.decode(["string"], data_bytes[4:])
        return error_string
    elif data_bytes[:4] == HexBytes("0x4e487b71"):
        (error_code,) = eth_abi.decode(["uint256"], data_bytes[4:])
        return solidity_panic_codes.get(error_code, f"Panic({error_code})")
    # old solidity: revert 'some string' case
    try:
        (error_string,) = eth_abi.decode(["string"], data_bytes)
        return error_string
    except Exception:
        pass
    # some custom error maybe it is with string?
    try:
        (error_string,) = eth_abi.decode(["string"], data_bytes[4:])
        return error_string
    except Exception:
        pass
    try:
        (error_string,) = eth_abi.decode(["string"], data_bytes[4:])
        return error_string
    except Exception:
        pass
    return error_string


def maybe_coerce_error(
    err: RuntimeError, pool_state: Any, gas_limit: int = None
) -> Exception:
    details = err.args[0]
    # we got bytes as data, so this was a revert
    if details.data.startswith("0x"):
        err = RuntimeError(
            f"Revert! Reason: {parse_solidity_error_message(details.data)}"
        )
        # we have gas information, check if this likely an out of gas err.
        if gas_limit is not None and details.gas_used is not None:
            # if we used up 97% or more issue a OutOfGas error.
            usage = details.gas_used / gas_limit
            if usage >= 0.97:
                return OutOfGas(
                    f"SimulationError: Likely out-of-gas. "
                    f"Used: {usage * 100:.2f}% of gas limit. "
                    f"Original error: {err}",
                    repr(pool_state),
                )
    elif "OutOfGas" in details.data:
        if gas_limit is not None:
            usage = details.gas_used / gas_limit
            usage_msg = f"Used: {usage * 100:.2f}% of gas limit. "
        else:
            usage_msg = ""
        return OutOfGas(
            f"SimulationError: out-of-gas. {usage_msg}Original error: {details.data}",
            repr(pool_state),
        )
    return err


def exec_rpc_method(url, method, params, timeout=240) -> dict:
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    headers = {"Content-Type": "application/json"}

    r = requests.post(url, data=json.dumps(payload), headers=headers, timeout=timeout)

    if r.status_code >= 400:
        raise RuntimeError(
            "RPC failed: status_code not ok. (method {}: {})".format(
                method, r.status_code
            )
        )
    data = r.json()

    if "result" in data:
        return data["result"]
    elif "error" in data:
        raise RuntimeError(
            "RPC failed with Error {} - {}".format(data["error"], method)
        )


def get_code_for_address(address: str, connection_string: str = None):
    if connection_string is None:
        connection_string = os.getenv("RPC_URL")
        if connection_string is None:
            raise EnvironmentError("RPC_URL environment variable is not set")

    method = "eth_getCode"
    params = [address, "latest"]

    try:
        code = exec_rpc_method(connection_string, method, params)
        return bytes.fromhex(code[2:])
    except RuntimeError as e:
        print(f"Error fetching code for address {address}: {e}")
        return None