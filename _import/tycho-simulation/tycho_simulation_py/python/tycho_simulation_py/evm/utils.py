import enum
import json
import os
from decimal import Decimal
from fractions import Fraction
from functools import lru_cache
from logging import getLogger
from typing import Final, Any, NamedTuple, Optional

import eth_abi
import eth_utils
from eth_typing import HexStr
from hexbytes import HexBytes
import requests
from tycho_simulation_py.evm import AccountUpdate

from . import SimulationEngine, AccountInfo
from .constants import EXTERNAL_ACCOUNT, MAX_BALANCE, ASSETS_FOLDER
from ..exceptions import OutOfGas
from ..models import Address, EthereumToken
from .storage import TychoDBSingleton

log = getLogger(__name__)


def decode_tycho_exchange(exchange: str) -> str:
    # removes vm prefix if present
    return exchange.split(":")[1] if "vm:" in exchange else exchange


def create_engine(
    mocked_tokens: list[Address],
    trace: bool = False,
    token_initial_state: Optional[dict[HexBytes, dict[int, int]]] = None,
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
            balance=0,
            nonce=0,
            code=get_contract_bytecode(ASSETS_FOLDER / "TokenProxy.bin"),
        )
        storage = None
        if token_initial_state is not None:
            storage = token_initial_state.get(HexBytes(t))
            if storage is not None:
                # TODO: move this to the TokenProxyOverwriteFactory
                storage[
                    0x6677C72CDEB41ACAF2B17EC8A6E275C4205F27DBFE4DE34EBAF2E928A7E610DB
                ] = int(t, 16)
        engine.init_account(
            address=t, account=info, mocked=True, permanent_storage=storage
        )
    engine.init_account(
        address=EXTERNAL_ACCOUNT,
        account=AccountInfo(balance=MAX_BALANCE, nonce=0, code=None),
        mocked=False,
        permanent_storage=None,
    )

    return engine


class ContractCompiler(enum.Enum):
    Solidity = enum.auto()
    Vyper = enum.auto()

    def compute_map_slot(self, map_base_slot: bytes, key: bytes) -> bytes:
        if self == ContractCompiler.Solidity:
            return eth_utils.keccak(key + map_base_slot)
        elif self == ContractCompiler.Vyper:
            return eth_utils.keccak(map_base_slot + key)
        else:
            raise NotImplementedError(
                f"compute_map_slot not implemented for {self.name}"
            )


class ERC20Slots(NamedTuple):
    balance_map: int
    allowance_map: int


class ERC20OverwriteFactory:
    def __init__(
        self,
        token: EthereumToken,
        token_slots: ERC20Slots = ERC20Slots(0, 1),
        compiler: ContractCompiler = ContractCompiler.Solidity,
    ):
        """
        Initialize the ERC20OverwriteFactory.

        Parameters:
            token: The token object.
        """
        self._token = token
        self._overwrites = dict()
        self._contract_compiler = compiler
        self._balance_slot: int = token_slots.balance_map
        self._allowance_slot: int = token_slots.allowance_map
        self._total_supply_slot: Final[int] = 2

    def set_balance(self, balance: int, owner: Address):
        """
        Set the balance for a given owner.

        Parameters:
            balance: The balance value.
            owner: The owner's address.
        """
        storage_index = get_storage_slot_at_key(
            HexStr(owner), self._balance_slot, self._contract_compiler
        )
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
            get_storage_slot_at_key(
                HexStr(owner), self._allowance_slot, self._contract_compiler
            ),
            self._contract_compiler,
        )
        self._overwrites[storage_index] = allowance
        log.log(
            5,
            f"Override allowance: token={self._token.address} owner={owner}"
            f"spender={spender} value={allowance} slot={storage_index}",
        )

    def set_total_supply(self, supply: int):
        """
        Set the total supply of the token.

        Parameters:
            supply: The total supply value.
        """
        self._overwrites[self._total_supply_slot] = supply
        log.log(
            5, f"Override total supply: token={self._token.address} supply={supply}"
        )

    def get_tycho_overwrites(self) -> dict[Address, dict[int, int]]:
        """
        Get the overwrites dictionary of previously collected values.

        Returns:
            dict[Address, dict]: A dictionary containing the token's address
            and the overwrites.
        """
        # Tycho returns lowercase addresses in state updates returned from simulation

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


class TokenProxyOverwriteFactory:
    """Factory for creating storage overwrites for the TokenProxy contract."""

    # Storage slots from TokenProxy.sol
    IMPLEMENTATION_SLOT = int(
        0x6677C72CDEB41ACAF2B17EC8A6E275C4205F27DBFE4DE34EBAF2E928A7E610DB
    )
    BALANCES_MAPPING_POSITION = int(
        0x474F5FD57EE674F7B6851BC6F07E751B49076DFB356356985B9DAF10E9ABC941
    )
    HAS_CUSTOM_BALANCE_POSITION = int(
        0x7EAD8EDE9DBB385B0664952C7462C9938A5821E6F78E859DA2E683216E99411B
    )
    CUSTOM_APPROVAL_MAPPING_POSITION = int(
        0x71A54E125991077003BEF7E7CA57369C919DAC6D2458895F1EAB4D03960F4AEB
    )
    HAS_CUSTOM_APPROVAL_MAPPING_POSITION = int(
        0x9F0C1BC0E9C3078F9AD5FC59C8606416B3FABCBD4C8353FED22937C66C866CE3
    )
    CUSTOM_NAME_POSITION = int(
        0xCC1E513FB5BDA80DC466AD9D44DF38805A8DEE4C82B3C6DF3D9B25D3D5355D1C
    )
    CUSTOM_SYMBOL_POSITION = int(
        0xDC17DD3380A9A034A702A2B2B1C6C25D39EBF0E89796E0D15E1E04D23E3BB221
    )
    CUSTOM_DECIMALS_POSITION = int(
        0xADD486B234562DE9AC745F036F538CDA2547EF6DBB4DA3FA1C017625F888A8E8
    )
    CUSTOM_TOTAL_SUPPLY_POSITION = int(
        0x6014AF1E8E9BB2844581B2FA9E5E3620181C3192EEFD3258319AEC23538DA9F5
    )
    HAS_CUSTOM_METADATA_POSITION = int(
        0x9F37243DE61714BE9CC00628D4B9BF9897AE670218AF52ADE6D192B4339D7616
    )

    def __init__(self, token: EthereumToken, proxy_address: HexBytes = None):
        """
        Initialize the TokenProxyOverwriteFactory.

        Parameters:
            token: The token object.
            proxy_address: The address of the original token contract. If None, it will not
            set the implementation address.
        """
        self._token = token
        self._overwrites = dict()
        if proxy_address is not None:
            self.set_implementation(proxy_address.hex())

    def set_implementation(self, implementation_addr: Address):
        """
        Set the implementation address for the proxy.

        Parameters:
            implementation_addr: The address of the implementation contract.
        """
        self._overwrites[self.IMPLEMENTATION_SLOT] = int(implementation_addr, 16)
        log.log(
            5,
            f"Set implementation: token={self._token.address} implementation={implementation_addr}",
        )

    def set_balance(self, balance: int, owner: Address):
        """
        Set the balance for a given owner.

        Parameters:
            balance: The balance value.
            owner: The owner's address.
        """
        # Set the balance in the custom storage slot
        storage_index = get_storage_slot_at_key(
            HexStr(owner), self.BALANCES_MAPPING_POSITION, ContractCompiler.Solidity
        )
        self._overwrites[storage_index] = balance

        # Set the has_custom_balance flag to true
        has_balance_index = get_storage_slot_at_key(
            HexStr(owner), self.HAS_CUSTOM_BALANCE_POSITION, ContractCompiler.Solidity
        )
        self._overwrites[has_balance_index] = 1  # true in Solidity

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
        # Set the allowance in the custom storage slot
        storage_index = get_storage_slot_at_key(
            HexStr(spender),
            get_storage_slot_at_key(
                HexStr(owner),
                self.CUSTOM_APPROVAL_MAPPING_POSITION,
                ContractCompiler.Solidity,
            ),
            ContractCompiler.Solidity,
        )
        self._overwrites[storage_index] = allowance

        # Set the has_custom_approval flag to true
        has_approval_index = get_storage_slot_at_key(
            HexStr(owner),
            self.HAS_CUSTOM_APPROVAL_MAPPING_POSITION,
            ContractCompiler.Solidity,
        )
        self._overwrites[has_approval_index] = 1  # true in Solidity

        log.log(
            5,
            f"Override allowance: token={self._token.address} owner={owner}"
            f"spender={spender} value={allowance} slot={storage_index}",
        )

    def set_total_supply(self, supply: int):
        """
        Set the total supply of the token.

        Parameters:
            supply: The total supply value.
        """
        self._overwrites[self.CUSTOM_TOTAL_SUPPLY_POSITION] = supply
        log.log(
            5, f"Override total supply: token={self._token.address} supply={supply}"
        )

    def set_name(self, name: str):
        """
        Set the token name.

        Parameters:
            name: The token name.
        """
        # Store the name in the custom storage slot
        self._overwrites[self.CUSTOM_NAME_POSITION] = int.from_bytes(
            name.encode(), "big"
        )

        # Set the has_custom_metadata flag for name to true
        has_metadata_index = get_storage_slot_at_key(
            "name", self.HAS_CUSTOM_METADATA_POSITION, ContractCompiler.Solidity
        )
        self._overwrites[has_metadata_index] = 1  # true in Solidity

        log.log(5, f"Override name: token={self._token.address} name={name}")

    def set_symbol(self, symbol: str):
        """
        Set the token symbol.

        Parameters:
            symbol: The token symbol.
        """
        # Store the symbol in the custom storage slot
        self._overwrites[self.CUSTOM_SYMBOL_POSITION] = int.from_bytes(
            symbol.encode(), "big"
        )

        # Set the has_custom_metadata flag for symbol to true
        has_metadata_index = get_storage_slot_at_key(
            "symbol", self.HAS_CUSTOM_METADATA_POSITION, ContractCompiler.Solidity
        )
        self._overwrites[has_metadata_index] = 1  # true in Solidity

        log.log(5, f"Override symbol: token={self._token.address} symbol={symbol}")

    def set_decimals(self, decimals: int):
        """
        Set the token decimals.

        Parameters:
            decimals: The number of decimals.
        """
        self._overwrites[self.CUSTOM_DECIMALS_POSITION] = decimals

        # Set the has_custom_metadata flag for decimals to true
        has_metadata_index = get_storage_slot_at_key(
            "decimals", self.HAS_CUSTOM_METADATA_POSITION, ContractCompiler.Solidity
        )
        self._overwrites[has_metadata_index] = 1  # true in Solidity

        log.log(
            5, f"Override decimals: token={self._token.address} decimals={decimals}"
        )

    def get_tycho_overwrites(self) -> dict[Address, dict[int, int]]:
        """
        Get the overwrites dictionary of previously collected values.

        Returns:
            dict[Address, dict]: A dictionary containing the token's address
            and the overwrites.
        """
        return {self._token.address.lower(): self._overwrites}

    def get_geth_overwrites(self) -> dict[Address, dict[int, int]]:
        """
        Get the overwrites dictionary in Geth format.

        Returns:
            dict[Address, dict]: A dictionary containing the token's address
            and the overwrites in Geth format.
        """
        formatted_overwrites = {
            HexBytes(key).hex(): "0x" + HexBytes(val).hex().lstrip("0x").zfill(64)
            for key, val in self._overwrites.items()
        }

        code = "0x" + get_contract_bytecode(ASSETS_FOLDER / "TokenProxy.bin").hex()
        return {self._token.address: {"stateDiff": formatted_overwrites, "code": code}}


def get_storage_slot_at_key(
    key: Address, mapping_slot: int, compiler=ContractCompiler.Solidity
) -> int:
    """Get storage slot index of a value stored at a certain key in a mapping

    Parameters
    ----------
    key
        Key in a mapping. This function is meant to work with ethereum addresses
        and accepts only strings.
    mapping_slot
        Storage slot at which the mapping itself is stored. See the examples for more
        explanation.

    compiler
        The compiler with which the target contract was compiled. Solidity and Vyper handle
        maps differently. This defaults to Solidity because it's the most used.

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
    slot_bytes = compiler.compute_map_slot(mapping_slot_bytes, key_bytes)
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
        path = f"{ASSETS_FOLDER}/{name_or_path}.abi"
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


def parse_account_info(accounts: list[dict[str, Any]]) -> list[AccountUpdate]:
    """Parses AccountInfo objects from a dictionary.

    Assumes all values are hex encoded bytes.
    """
    parsed = []
    for account in accounts:
        address = account["address"]
        balance = int(account["native_balance"], 16)
        code = bytearray.fromhex(account["code"][2:])
        # apply account updates
        slots = {int(k, 16): int(v, 16) for k, v in account["slots"].items()}
        parsed.append(
            AccountUpdate(
                address=address,
                chain=account["chain"],
                slots=slots,
                balance=balance,
                code=code,
                change="Update",
            )
        )

    return parsed
