import datetime
from decimal import Decimal, localcontext, Context, ROUND_FLOOR, InvalidOperation
from enum import Enum, IntEnum, auto
from fractions import Fraction
from logging import getLogger
from typing import Union

from pydantic import BaseModel, Field, PrivateAttr

Address = str

log = getLogger(__name__)


class Blockchain(Enum):
    ethereum = "ethereum"
    arbitrum = "arbitrum"
    polygon = "polygon"
    zksync = "zksync"


class EVMBlock(BaseModel):
    id: int
    ts: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    hash_: str


class EthereumToken(BaseModel):
    symbol: str
    address: str
    decimals: int
    gas: Union[int, list[int]] = 29000
    _hash: int = PrivateAttr(default=None)

    def to_onchain_amount(self, amount: Union[float, Decimal, str]) -> int:
        """Converts floating-point numerals to an integer, by shifting right by the
        token's maximum amount of decimals (e.g.: 1.000000 becomes 1000000).
        For the reverse operation please see self.from_onchain_amount
        """
        if not isinstance(amount, Decimal):
            log.warning(f"Expected variable of type Decimal. Got {type(amount)}.")

        with localcontext(Context(rounding=ROUND_FLOOR, prec=256)):
            amount = Decimal(str(amount)) * (10 ** self.decimals)
            try:
                amount = amount.quantize(Decimal("1.0"))
            except InvalidOperation:
                log.error(
                    f"Quantize failed for {self.symbol}, {amount}, {self.decimals}"
                )
            return int(amount)

    def from_onchain_amount(
        self, onchain_amount: Union[int, Fraction], quantize: bool = True
    ) -> Decimal:
        """Converts an Integer to a quantized decimal, by shifting left by the token's
        maximum amount of decimals (e.g.: 1000000 becomes 1.000000 for a 6-decimal token
        For the reverse operation please see self.to_onchain_amount

        If the onchain_amount is too low, then using quantize can underflow without
        raising and the offchain amount returned is 0.
        See _decimal.Decimal.quantize docstrings for details.

        Quantize is needed for UniswapV2.
        """
        with localcontext(Context(rounding=ROUND_FLOOR, prec=256)):
            if isinstance(onchain_amount, Fraction):
                return (
                    Decimal(onchain_amount.numerator)
                    / Decimal(onchain_amount.denominator)
                    / Decimal(10 ** self.decimals)
                ).quantize(Decimal(f"{1 / 10 ** self.decimals}"))
            if quantize is True:
                try:
                    amount = (
                        Decimal(str(onchain_amount)) / 10 ** self.decimals
                    ).quantize(Decimal(f"{1 / 10 ** self.decimals}"))
                except InvalidOperation:
                    amount = Decimal(str(onchain_amount)) / Decimal(10 ** self.decimals)
            else:
                amount = Decimal(str(onchain_amount)) / Decimal(10 ** self.decimals)
            return amount

    def __repr__(self):
        return self.symbol

    def __str__(self):
        return self.symbol

    def __eq__(self, other) -> bool:
        # this is faster than calling custom __hash__, due to cache check
        return other.address == self.address

    def __hash__(self) -> int:
        if self._hash is None:
            # caching the hash saves time during graph search
            self._hash = hash(self.address)
        return self._hash


class DatabaseType(Enum):
    # Make call to the node each time it needs a storage (unless cached from a previous call).
    rpc_reader = "rpc_reader"
    # Connect to Tycho and cache the whole state of a target contract, the state is continuously updated by Tycho.
    # To use this we need Tycho to be configured to index the target contract state.
    tycho = "tycho"


class Capability(IntEnum):
    SellSide = auto()
    BuySide = auto()
    PriceFunction = auto()
    FeeOnTransfer = auto()
    ConstantPrice = auto()
    TokenBalanceIndependent = auto()
    ScaledPrice = auto()


class SynchronizerState(Enum):
    started = "started"
    ready = "ready"
    stale = "stale"
    delayed = "delayed"
    advanced = "advanced"
    ended = "ended"
