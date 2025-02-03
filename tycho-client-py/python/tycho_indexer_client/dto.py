from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Union
from uuid import UUID

from hexbytes import HexBytes as _HexBytes
from pydantic import BaseModel, Field, root_validator, RootModel
from pydantic_core.core_schema import ValidationInfo


class HexBytes(_HexBytes):
    @classmethod
    def __get_validators__(cls):
        # one or more validators may be yielded which will be called in the
        # order to validate the input, each validator will receive as an input
        # the value returned from the previous validator
        yield cls.validate

    @classmethod
    def __get_pydantic_json_schema__(cls, field_schema):
        # __modify_schema__ should mutate the dict it receives in place,
        # the returned value will be ignored
        field_schema.update(
            # some example postcodes
            examples=["0xBadBad"]
        )

    @classmethod
    def validate(cls, v: str, _: ValidationInfo):
        data = _HexBytes(v)

        return cls(data)

    def __int__(self):
        if self.hex() != "0x":
            return int(self.hex(), 16)
        else:
          return 0


class Chain(str, Enum):
    ethereum = "ethereum"
    starknet = "starknet"
    arbitrum = "arbitrum"
    base = "base"


class ChangeType(str, Enum):
    update = "Update"
    deletion = "Deletion"
    creation = "Creation"
    unspecified = "Unspecified"


class ExtractorIdentity(BaseModel):
    chain: Chain
    name: str


class Command(BaseModel):
    class Subscribe(BaseModel):
        extractor_id: ExtractorIdentity
        include_state: bool

    class Unsubscribe(BaseModel):
        subscription_id: UUID

    method: Union[Subscribe, Unsubscribe]


class Response(BaseModel):
    class NewSubscription(BaseModel):
        extractor_id: ExtractorIdentity
        subscription_id: UUID

    class SubscriptionEnded(BaseModel):
        subscription_id: UUID

    method: Union[NewSubscription, SubscriptionEnded]


class Header(BaseModel):
    number: int
    hash: HexBytes
    parent_hash: HexBytes
    revert: bool


class Block(BaseModel):
    number: int
    hash: HexBytes
    parent_hash: HexBytes
    chain: Chain
    ts: datetime


class BlockParam(BaseModel):
    hash: Optional[HexBytes] = None
    chain: Optional[Chain] = None
    number: Optional[int] = None


class ComponentBalance(BaseModel):
    token: HexBytes
    balance: HexBytes
    balance_float: float
    modify_tx: HexBytes
    component_id: str


class TokenBalances(RootModel[Dict[HexBytes, ComponentBalance]]):

    def items(self):
            return self.__root__.items()

class AccountUpdate(BaseModel):
    address: HexBytes
    chain: Chain
    slots: Dict[HexBytes, HexBytes]
    balance: Optional[HexBytes] = None
    code: Optional[HexBytes] = None
    change: ChangeType


class ProtocolStateDelta(BaseModel):
    component_id: str
    updated_attributes: Dict[str, HexBytes]
    deleted_attributes: Set[str]


class ProtocolComponent(BaseModel):
    id: str
    protocol_system: str
    protocol_type_name: str
    chain: Chain
    tokens: List[HexBytes]
    contract_ids: List[HexBytes]
    static_attributes: Dict[str, HexBytes]
    change: ChangeType
    creation_tx: HexBytes
    created_at: datetime


class ResponseToken(BaseModel):
    chain: Chain
    address: HexBytes = Field(..., example="0xc9f2e6ea1637E499406986ac50ddC92401ce1f58")
    symbol: str = Field(..., example="WETH")
    decimals: int
    tax: int
    gas: List[Optional[int]]
    quality: int


class BlockChanges(BaseModel):
    extractor: str
    chain: Chain
    block: Block
    finalized_block_height: int
    revert: bool
    new_tokens: Dict[HexBytes, ResponseToken] = Field(default_factory=dict)
    account_updates: Dict[HexBytes, AccountUpdate]
    state_updates: Dict[str, ProtocolStateDelta]
    new_protocol_components: Dict[str, ProtocolComponent]
    deleted_protocol_components: Dict[str, ProtocolComponent]
    component_balances: Dict[str, TokenBalances]
    component_tvl: Dict[str, float]


class ResponseProtocolState(BaseModel):
    component_id: str
    attributes: Dict[str, HexBytes]
    balances: Dict[HexBytes, HexBytes]


class ComponentWithState(BaseModel):
    state: ResponseProtocolState
    component: ProtocolComponent


class ResponseAccount(BaseModel):
    chain: Chain
    address: HexBytes
    title: str
    slots: Dict[HexBytes, HexBytes]
    native_balance: HexBytes = Field(alias="balance")
    code: HexBytes
    code_hash: HexBytes
    balance_modify_tx: HexBytes
    code_modify_tx: HexBytes
    creation_tx: Optional[HexBytes] = None

    class Config:
        populate_by_name = True

    @property
    def balance(self) -> HexBytes:
        return self.native_balance

    @property
    def change(self) -> ChangeType:
        return ChangeType.creation


class Snapshot(BaseModel):
    states: Dict[str, ComponentWithState] = Field(default_factory=dict)
    vm_storage: Dict[HexBytes, ResponseAccount] = Field(default_factory=dict)


class StateSyncMessage(BaseModel):
    header: Header
    snapshots: Snapshot
    deltas: Optional[BlockChanges] = None
    removed_components: Dict[str, ProtocolComponent] = Field(default_factory=dict)


class SynchronizerStateEnum(str, Enum):
    started = "started"
    ready = "ready"
    stale = "stale"
    delayed = "delayed"
    advanced = "advanced"
    ended = "ended"


class SynchronizerState(BaseModel):
    status: SynchronizerStateEnum
    header: Optional[Header] = None

    def __init__(self, status: SynchronizerStateEnum, **kwargs):
        if len(kwargs) == 4:
            header = Header(**kwargs)
        else:
            header = kwargs.get("header", None)
        super().__init__(status=status, header=header)


class FeedMessage(BaseModel):
    state_msgs: dict[str, StateSyncMessage]
    sync_states: dict[str, SynchronizerState]

    def __repr__(self):
        return f"FeedMessage(n_state_msgs={len(self.state_msgs)}, n_sync_states={len(self.sync_states)})"


# Client Parameters


class ProtocolId(BaseModel):
    chain: Chain
    id: str


class ContractId(BaseModel):
    address: HexBytes
    chain: Chain


class VersionParams(BaseModel):
    block: Optional[BlockParam] = None
    timestamp: Optional[datetime] = None


class ProtocolComponentsParams(BaseModel):
    protocol_system: Optional[str] = None
    component_addresses: Optional[List[HexBytes]] = Field(default=None)
    tvl_gt: Optional[int] = None

    class Config:
        populate_by_name = True


class ProtocolStateParams(BaseModel):
    include_balances: Optional[bool] = True
    protocol_ids: Optional[List[ProtocolId]] = Field(default=None)
    protocol_system: Optional[str] = Field(default=None)
    version: Optional[VersionParams] = None

    class Config:
        populate_by_name = True
        use_enum_values = True


class ContractStateParams(BaseModel):
    contract_ids: Optional[List[str]] = Field(default=None)
    protocol_system: Optional[str] = Field(default=None)
    version: Optional[VersionParams] = None

    # Backward compatibility with old ContractId format
    # To be removed in the future
    @root_validator(pre=True)
    def handle_old_contract_id_format(cls, values):
        contract_ids = values.get('contract_ids')
        if contract_ids and isinstance(contract_ids[0], ContractId):
            # Handle old format: List of ContractId objects
            values['contract_ids'] = [c.address.hex() for c in contract_ids]
        return values

    class Config:
        populate_by_name = True


class PaginationParams(BaseModel):
    page: Optional[int] = None
    page_size: Optional[int] = None


class TokensParams(BaseModel):
    min_quality: Optional[int] = None
    pagination: Optional[PaginationParams] = None
    token_addresses: Optional[List[HexBytes]] = Field(default=None)
    traded_n_days_ago: Optional[int] = None

    class Config:
        populate_by_name = True
