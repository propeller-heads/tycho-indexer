import functools
import itertools
from collections import defaultdict
from copy import deepcopy
from decimal import Decimal
from fractions import Fraction
from logging import getLogger
from typing import Optional, cast, TypeVar, Annotated

from eth_typing import HexStr
from protosim_py import SimulationEngine, AccountInfo
from pydantic import BaseModel, PrivateAttr, Field

from .adapter_contract import AdapterContract
from .constants import MAX_BALANCE, EXTERNAL_ACCOUNT
from .exceptions import RecoverableSimulationException
from .models import EVMBlock, Capability, Address, EthereumToken
from .utils import (
    create_engine,
    get_contract_bytecode,
    frac_to_decimal,
    ERC20OverwriteFactory,
)

ADAPTER_ADDRESS = "0xA2C5C98A892fD6656a7F39A2f63228C0Bc846270"

log = getLogger(__name__)
TPoolState = TypeVar("TPoolState", bound="ThirdPartyPool")


class ThirdPartyPool(BaseModel):
    id_: str
    tokens: tuple[EthereumToken, ...]
    balances: dict[Address, Decimal]
    block: EVMBlock
    spot_prices: dict[tuple[EthereumToken, EthereumToken], Decimal]
    trading_fee: Decimal
    exchange: str
    minimum_gas: int

    _engine: SimulationEngine = PrivateAttr(default=None)

    adapter_contract_name: str
    """The adapters contract name. Used to look up the byte code for the adapter."""
    _adapter_contract: AdapterContract = PrivateAttr(default=None)

    stateless_contracts: dict[str, bytes] = {}
    """The address to bytecode map of all stateless contracts used by the protocol for simulations."""

    capabilities: set[Capability] = Field(default_factory=lambda: {Capability.SellSide})
    """The supported capabilities of this pool."""

    balance_owner: Optional[str] = None
    """The contract address for where protocol balances are stored (i.e. a vault contract).
    If given, balances will be overwritten here instead of on the pool contract during simulations."""

    block_lasting_overwrites: defaultdict[
        Address,
        Annotated[dict[int, int], Field(default_factory=lambda: defaultdict[dict])],
    ] = Field(default_factory=lambda: defaultdict(dict))

    """Storage overwrites that will be applied to all simulations. They will be cleared
    when ``clear_all_cache`` is called, i.e. usually at each block. Hence the name."""

    trace: bool = False

    def __init__(self, **data):
        super().__init__(**data)
        self._set_engine(data.get("engine", None))
        self.balance_owner = data.get("balance_owner", None)
        self._adapter_contract = AdapterContract(ADAPTER_ADDRESS, self._engine)
        self._set_capabilities()
        if len(self.spot_prices) == 0:
            self._set_spot_prices()

    def _set_engine(self, engine: Optional[SimulationEngine]):
        """Set instance's simulation engine. If no engine given, make a default one.

        If engine is already set, this is a noop.

        The engine will have the specified adapter contract mocked, as well as the
        tokens used by the pool.

        Parameters
        ----------
        engine
            Optional simulation engine instance.
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
                    code=get_contract_bytecode(self.adapter_contract_name),
                ),
                mocked=False,
                permanent_storage=None,
            )
            for addr, bytecode in self.stateless_contracts.items():
                engine.init_account(
                    address=addr,
                    account=AccountInfo(balance=0, nonce=0, code=bytecode),
                    mocked=False,
                    permanent_storage=None,
                )
        self._engine = engine

    def _set_spot_prices(self):
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
                overwrites=self.block_lasting_overwrites,
            )[0]
            if Capability.ScaledPrice in self.capabilities:
                self.spot_prices[(t0, t1)] = frac_to_decimal(frac)
            else:
                scaled = frac * Fraction(10 ** t0.decimals, 10 ** t1.decimals)
                self.spot_prices[(t0, t1)] = frac_to_decimal(scaled)

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
        self.capabilities = functools.reduce(set.intersection, capabilities)
        if len(self.capabilities) < max_capabilities:
            log.warning(
                f"Pool {self.id_} hash different capabilities depending on the token pair!"
            )

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
        trade, state_changes = self._adapter_contract.swap(
            cast(HexStr, self.id_),
            sell_token,
            buy_token,
            False,
            sell_token.to_onchain_amount(sell_amount),
            block=self.block,
            overwrites=self._get_overwrites(sell_token, buy_token),
        )
        new_state = self._duplicate()
        for address, state_update in state_changes.items():
            for slot, value in state_update.storage.items():
                new_state.block_lasting_overwrites[address][slot] = value

        new_price = frac_to_decimal(trade.price)
        if new_price != Decimal(0):
            new_state.spot_prices = {
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
        return _merge(self.block_lasting_overwrites, token_overwrites)

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
        overwrites = ERC20OverwriteFactory(sell_token)
        overwrites.set_balance(max_amount, EXTERNAL_ACCOUNT)
        overwrites.set_allowance(
            allowance=max_amount, owner=EXTERNAL_ACCOUNT, spender=ADAPTER_ADDRESS
        )
        res.append(overwrites.get_protosim_overwrites())

        # we need to merge the dictionaries because balance overwrites may target
        # the same token address.
        res = functools.reduce(_merge, res)
        return res

    def _get_balance_overwrites(self) -> dict[Address, dict[int, int]]:
        balance_overwrites = {}
        address = self.balance_owner or self.id_
        for t in self.tokens:
            overwrites = ERC20OverwriteFactory(t)
            overwrites.set_balance(
                t.to_onchain_amount(self.balances[t.address]), address
            )
            balance_overwrites.update(overwrites.get_protosim_overwrites())
        return balance_overwrites

    def _duplicate(self: type["ThirdPartyPool"]) -> "ThirdPartyPool":
        """Make a new instance identical to self that shares the same simulation engine.

        Note that the new and current state become coupled in a way that they must
        simulate the same block. This is fine, see
        https://datarevenue.atlassian.net/browse/ROC-1301

        Not naming this method _copy to not confuse with Pydantic's .copy method.
        """
        return type(self)(
            exchange=self.exchange,
            adapter_contract_name=self.adapter_contract_name,
            block=self.block,
            id_=self.id_,
            tokens=self.tokens,
            spot_prices=self.spot_prices.copy(),
            trading_fee=self.trading_fee,
            block_lasting_overwrites=deepcopy(self.block_lasting_overwrites),
            engine=self._engine,
            balances=self.balances,
            minimum_gas=self.minimum_gas,
            balance_owner=self.balance_owner,
            stateless_contracts=self.stateless_contracts,
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
        self._set_spot_prices()


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
