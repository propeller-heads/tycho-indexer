import datetime
from enum import Enum
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
