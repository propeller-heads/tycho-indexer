import datetime
from enum import Enum
from typing import Union

from pydantic import BaseModel, Field


class Blockchain(Enum):
    ethereum = "ethereum"
    arbitrum = "arbitrum"
    polygon = "polygon"
    zksync = "zksync"


class EVMBlock(BaseModel):
    id: int
    ts: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    hash_: str


class ThirdPartyPool:
    pass


class EthereumToken(BaseModel):
    symbol: str
    address: str
    decimals: int
    gas: Union[int, list[int]] = 29000
