import functools
import itertools
import time
from collections import defaultdict
from copy import deepcopy
from decimal import Decimal
from fractions import Fraction
from logging import getLogger
from typing import Optional, cast, TypeVar

import eth_abi
from eth_utils import keccak
from eth_typing import HexStr

from . import token
from . import SimulationEngine, AccountInfo, SimulationParameters
from .adapter_contract import AdapterContract
from .constants import MAX_BALANCE, EXTERNAL_ACCOUNT
from ..exceptions import RecoverableSimulationException
from ..models import EVMBlock, Capability, Address, EthereumToken
from .utils import (
    ContractCompiler,
    create_engine,
    get_contract_bytecode,
    frac_to_decimal,
    ERC20OverwriteFactory,
    get_code_for_address,
)

ADAPTER_ADDRESS = "0xA2C5C98A892fD6656a7F39A2f63228C0Bc846270"

log = getLogger(__name__)
TPoolState = TypeVar("TPoolState", bound="ThirdPartyPool")


class ThirdPartyPool:
    def __init__(
        self,
        id_: str,
        tokens: tuple[EthereumToken, ...],
        balances: dict[Address, Decimal],
        block: EVMBlock,
        adapter_contract_path: str,
        marginal_prices: dict[tuple[EthereumToken, EthereumToken], Decimal] = None,
        stateless_contracts: dict[str, bytes] = None,
        capabilities: set[Capability] = None,
        balance_owner: Optional[str] = None,
        block_lasting_overwrites: defaultdict[Address, dict[int, int]] = None,
        manual_updates: bool = False,
        trace: bool = False,
        involved_contracts=None,
        token_storage_slots=None,
    ):
        self.id_ = id_
        """The pools identifier."""

        self.tokens = tokens
        """The pools tokens."""

        self.balances = balances
        """The pools token balances."""

        self.block = block
        """The current block, will be used to set vm context."""

        self.marginal_prices = marginal_prices
        """Marginal prices of the pool by token pair."""

        self.adapter_contract_path = adapter_contract_path
        """The adapters contract name. Used to look up the byte code for the adapter."""

        self.stateless_contracts: dict[str, Optional[bytes]] = stateless_contracts or {}
        """The address to bytecode map of all stateless contracts used by the protocol 
        for simulations. If the bytecode is None, an RPC call is done to get the code from our node"""

        self.capabilities: set[Capability] = capabilities or {Capability.SellSide}
        """The supported capabilities of this pool."""

        self.balance_owner: Optional[str] = balance_owner
        """The contract address for where protocol balances are stored (i.e. a vault 
        contract). If given, balances will be overwritten here instead of on the pool 
        contract during simulations."""

        self.block_lasting_overwrites: defaultdict[Address, dict[int, int]] = (
            block_lasting_overwrites or defaultdict(dict)
        )
        """Storage overwrites that will be applied to all simulations. They will be cleared
        when ``clear_all_cache`` is called, i.e. usually at each block. Hence the name."""

        self.manual_updates: bool = manual_updates
        """Indicates if the protocol uses custom update rules and requires update 
        triggers to recalculate spot prices ect. Default is to update on all changes on 
        the pool."""

        self.trace: bool = trace
        """If set, vm will emit detailed traces about the execution."""

        self.involved_contracts: set[Address] = involved_contracts or set()
        """A set of all contract addresses involved in the simulation of this pool."""

        self.token_storage_slots: dict[Address, tuple[tuple[int, int], ContractCompiler]] = (
                token_storage_slots or {}
        )
        """Allows the specification of custom storage slots for token allowances and
        balances. This is particularly useful for token contracts involved in protocol
        logic that extends beyond simple transfer functionality.
        """

        self._engine: Optional[SimulationEngine] = None
        self._set_engine()
        self._adapter_contract = AdapterContract(ADAPTER_ADDRESS, self._engine)
        self._set_capabilities()
        self._init_token_storage_slots()
        if len(self.marginal_prices) == 0:
            self._set_marginal_prices()

    def _set_engine(self):
        """Set instance's simulation engine. If no engine given, make a default one.

        If engine is already set, this is a noop.

        The engine will have the specified adapter contract mocked, as well as the
        tokens used by the pool.
        """
        if self._engine is not None:
            return
        else:
            engine = create_engine([t.address for t in self.tokens], trace=self.trace)
            engine.init_account(
                address="0x0000000000000000000000000000000000000000",
                account=AccountInfo(balance=0, nonce=0),
                mocked=False,
                permanent_storage=None,
            )
            engine.init_account(
                address="0x0000000000000000000000000000000000000004",
                account=AccountInfo(balance=0, nonce=0),
                mocked=False,
                permanent_storage=None,
            )
            engine.init_account(
                address=ADAPTER_ADDRESS,
                account=AccountInfo(
                    balance=MAX_BALANCE,
                    nonce=0,
                    code=get_contract_bytecode(self.adapter_contract_path),
                ),
                mocked=False,
                permanent_storage=None,
            )
            for addr, bytecode in self.stateless_contracts.items():
                if bytecode is None:
                    if addr.startswith("call"):
                        addr = self._get_address_from_call(engine, addr)
                    bytecode = get_code_for_address(addr)
                engine.init_account(
                    address=addr,
                    account=AccountInfo(balance=0, nonce=0, code=bytecode),
                    mocked=False,
                    permanent_storage=None,
                )

        self._engine = engine

    def _set_marginal_prices(self):
        """Set the spot prices for this pool.

        We currently require the price function capability for now.
        """
        self._ensure_capability(Capability.PriceFunction)
        for t0, t1 in itertools.permutations(self.tokens, 2):
            sell_amount = t0.to_onchain_amount(
                self.get_sell_amount_limit(t0, t1) * Decimal("0.01")
            )
            frac = self._adapter_contract.price(
                cast(HexStr, self.id_),
                t0,
                t1,
                [sell_amount],
                block=self.block,
                overwrites=self._get_overwrites(t0,t1),
            )[0]
            if Capability.ScaledPrices in self.capabilities:
                self.marginal_prices[(t0, t1)] = frac_to_decimal(frac)
            else:
                scaled = frac * Fraction(10**t0.decimals, 10**t1.decimals)
                self.marginal_prices[(t0, t1)] = frac_to_decimal(scaled)

    def _ensure_capability(self, capability: Capability):
        """Ensures the protocol/adapter implement a certain capability."""
        if capability not in self.capabilities:
            raise NotImplemented(f"{capability} not available!")

    def _set_capabilities(self):
        """Sets capabilities of the pool."""
        capabilities = []
        for t0, t1 in itertools.permutations(self.tokens, 2):
            capabilities.append(
                self._adapter_contract.get_capabilities(cast(HexStr, self.id_), t0, t1)
            )
        max_capabilities = max(map(len, capabilities))
        self.capabilities = set(functools.reduce(set.intersection, capabilities))
        if len(self.capabilities) < max_capabilities:
            log.warning(
                f"Pool {self.id_} hash different capabilities depending on the token pair!"
            )

    def _init_token_storage_slots(self):
        for t in self.tokens:
            if (
                t.address in self.involved_contracts
                and t.address not in self.token_storage_slots
            ):
                self.token_storage_slots[t.address] = slots = token.brute_force_slots(
                    t, self.block, self._engine
                )
                log.debug(f"Using custom storage slots for {t.address}: {slots}")

    def get_amount_out(
        self: TPoolState,
        sell_token: EthereumToken,
        sell_amount: Decimal,
        buy_token: EthereumToken,
    ) -> tuple[Decimal, int, TPoolState]:
        # if the pool has a hard limit and the sell amount exceeds that, simulate and
        # raise a partial trade
        if Capability.HardLimits in self.capabilities:
            sell_limit = self.get_sell_amount_limit(sell_token, buy_token)
            if sell_amount > sell_limit:
                partial_trade = self._get_amount_out(sell_token, sell_limit, buy_token)
                raise RecoverableSimulationException(
                    "Sell amount exceeds sell limit",
                    repr(self),
                    partial_trade + (sell_limit,),
                )

        return self._get_amount_out(sell_token, sell_amount, buy_token)

    def _get_amount_out(
        self: TPoolState,
        sell_token: EthereumToken,
        sell_amount: Decimal,
        buy_token: EthereumToken,
    ) -> tuple[Decimal, int, TPoolState]:
        overwrites = self._get_overwrites(sell_token, buy_token)
        trade, state_changes = self._adapter_contract.swap(
            cast(HexStr, self.id_),
            sell_token,
            buy_token,
            False,
            sell_token.to_onchain_amount(sell_amount),
            block=self.block,
            overwrites=overwrites,
        )
        new_state = self._duplicate()
        for address, state_update in state_changes.items():
            for slot, value in state_update.storage.items():
                new_state.block_lasting_overwrites[address][slot] = value

        new_price = frac_to_decimal(trade.price)
        if new_price != Decimal(0):
            new_state.marginal_prices = {
                (sell_token, buy_token): new_price,
                (buy_token, sell_token): Decimal(1) / new_price,
            }

        buy_amount = buy_token.from_onchain_amount(trade.received_amount)

        return buy_amount, trade.gas_used, new_state

    def _get_overwrites(
        self, sell_token: EthereumToken, buy_token: EthereumToken, **kwargs
    ) -> dict[Address, dict[int, int]]:
        """Get an overwrites dictionary to use in a simulation.

        The returned overwrites include block-lasting overwrites set on the instance
        level, and token-specific overwrites that depend on passed tokens.
        """
        token_overwrites = self._get_token_overwrites(sell_token, buy_token, **kwargs)
        return _merge(self.block_lasting_overwrites.copy(), token_overwrites)

    def _get_token_overwrites(
        self, sell_token: EthereumToken, buy_token: EthereumToken, max_amount=None
    ) -> dict[Address, dict[int, int]]:
        """Creates overwrites for a token.

        Funds external account with enough tokens to execute swaps. Also creates a
        corresponding approval to the adapter contract.

        If the protocol reads its own token balances, the balances for the underlying
        pool contract will also be overwritten.
        """
        res = []
        if Capability.TokenBalanceIndependent not in self.capabilities:
            res = [self._get_balance_overwrites()]

        # avoids recursion if using this method with get_sell_amount_limit
        if max_amount is None:
            max_amount = sell_token.to_onchain_amount(
                self.get_sell_amount_limit(sell_token, buy_token)
            )
        slots, compiler = self.token_storage_slots.get(sell_token.address, ((0, 1), ContractCompiler.Solidity))
        overwrites = ERC20OverwriteFactory(
            sell_token,
            token_slots=slots,
            compiler=compiler
        )
        overwrites.set_balance(max_amount, EXTERNAL_ACCOUNT)
        overwrites.set_allowance(
            allowance=max_amount, owner=EXTERNAL_ACCOUNT, spender=ADAPTER_ADDRESS
        )
        res.append(overwrites.get_tycho_overwrites())

        # we need to merge the dictionaries because balance overwrites may target
        # the same token address.
        res = functools.reduce(_merge, res)
        return res

    def _get_balance_overwrites(self) -> dict[Address, dict[int, int]]:
        balance_overwrites = {}
        address = self.balance_owner or self.id_
        for t in self.tokens:
            slots = (0, 1)
            compiler = ContractCompiler.Solidity
            if t.address in self.involved_contracts:
                slots, compiler = self.token_storage_slots.get(t.address)
            overwrites = ERC20OverwriteFactory(t, token_slots=slots, compiler=compiler)
            overwrites.set_balance(
                t.to_onchain_amount(self.balances[t.address]), address
            )
            balance_overwrites.update(overwrites.get_tycho_overwrites())
        return balance_overwrites

    def _duplicate(self: "ThirdPartyPool") -> "ThirdPartyPool":
        """Make a new instance identical to self that shares the same simulation engine.

        Note that the new and current state become coupled in a way that they must
        simulate the same block. This is fine, see
        https://datarevenue.atlassian.net/browse/ROC-1301

        Not naming this method _copy to not confuse with Pydantic's .copy method.
        """
        return type(self)(
            id_=self.id_,
            tokens=self.tokens,
            balances=self.balances,
            block=self.block,
            marginal_prices=self.marginal_prices.copy(),
            adapter_contract_path=self.adapter_contract_path,
            stateless_contracts=self.stateless_contracts,
            capabilities=self.capabilities,
            balance_owner=self.balance_owner,
            block_lasting_overwrites=deepcopy(self.block_lasting_overwrites),
            manual_updates=self.manual_updates,
            trace=self.trace,
        )

    def get_sell_amount_limit(
        self, sell_token: EthereumToken, buy_token: EthereumToken
    ) -> Decimal:
        """
        Retrieves the sell amount of the given token.

        For pools with more than 2 tokens, the sell limit is obtain for all possible buy token
        combinations and the minimum is returned.
        """
        limit = self._adapter_contract.get_limits(
            cast(HexStr, self.id_),
            sell_token,
            buy_token,
            block=self.block,
            overwrites=self._get_overwrites(
                sell_token, buy_token, max_amount=MAX_BALANCE // 100
            ),
        )[0]
        return sell_token.from_onchain_amount(limit)

    def clear_all_cache(self):
        self._engine.clear_temp_storage()
        self.block_lasting_overwrites = defaultdict(dict)
        self._set_marginal_prices()

    def _get_address_from_call(self, engine, decoded):
        selector = keccak(text=decoded.split(":")[-1])[:4]
        sim_result = engine.run_sim(
            SimulationParameters(
                data=bytearray(selector),
                to=decoded.split(":")[1],
                block_number=self.block.id,
                timestamp=int(time.time()),
                overrides={},
                caller=EXTERNAL_ACCOUNT,
                value=0,
            )
        )
        address = eth_abi.decode(["address"], bytearray(sim_result.result))
        return address[0]


def _merge(a: dict, b: dict, path=None):
    """
    Merges two dictionaries (a and b) deeply. This means it will traverse and combine
    their nested dictionaries too if present.

    Parameters:
    a (dict): The first dictionary to merge.
    b (dict): The second dictionary to merge into the first one.
    path (list, optional): An internal parameter used during recursion
        to keep track of the ancestry of nested dictionaries.

    Returns:
    a (dict): The merged dictionary which includes all key-value pairs from `b`
        added into `a`. If they have nested dictionaries with same keys, those are also merged.
        On key conflicts, preference is given to values from b.
    """
    if path is None:
        path = []
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                _merge(a[key], b[key], path + [str(key)])
        else:
            a[key] = b[key]
    return a
