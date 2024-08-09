from abc import ABC
from collections import defaultdict
from logging import getLogger
from typing import Callable, Union

from eth_utils import to_checksum_address
from tycho_client import dto
from tycho_client.dto import ComponentWithState, BlockChanges, HexBytes

from . import AccountUpdate, BlockHeader
from ..models import EVMBlock, EthereumToken
from .pool_state import ThirdPartyPool
from .storage import TychoDBSingleton
from .utils import decode_tycho_exchange

log = getLogger(__name__)


class TychoDecodeError(Exception):
    def __init__(self, msg: str, pool_id: str):
        super().__init__(msg)
        self.pool_id = pool_id


class TychoDecoder(ABC):
    ignored_pools: set
    """Component ids for pools that failed to decode snapshots and whose state deltas must be skipped."""

    def __init__(self):
        self.pool_states = {}
        self.ignored_pools = set()

    @staticmethod
    def decode_id(component_id: str) -> str:
        # default assumption is that the id does not need to be altered
        return component_id


class ThirdPartyPoolTychoDecoder(TychoDecoder):
    """ThirdPartyPool decoder for protocol messages from the Tycho feed"""

    contract_pools: dict[str, list[str]]
    """Mapping of contracts to the pool ids for the pools they affect"""
    component_pool_id: dict[str, str]
    """Mapping of component ids to their internal pool id"""

    def __init__(
        self,
        token_factory_func: Callable[[list[str]], list[EthereumToken]],
        adapter_contract: str,
        minimum_gas: int,
        trace: bool = False,
    ):
        super().__init__()
        self.contract_pools = defaultdict(list)
        self.component_pool_id = {}
        self.token_factory_func = token_factory_func
        self.adapter_contract = adapter_contract
        self.minimum_gas = minimum_gas
        self.trace = trace

    def decode_snapshot(
        self, snapshot: dto.Snapshot, block: EVMBlock
    ) -> dict[str, ThirdPartyPool]:
        pools = {}
        self._handle_vm_updates(block, snapshot.vm_storage)
        for snap in snapshot.states.values():
            try:
                pool = self.decode_pool_state(snap, block)
                pools[pool.id_] = pool
            except TychoDecodeError as e:
                log.error(f"Failed to decode third party snapshot: {e}")
                self.ignored_pools.add(snap.component.id)
                continue

        if pools:
            exchange = decode_tycho_exchange(
                next(iter(snapshot.states.values())).component.protocol_system
            )
            log.debug(
                f"Finished decoding {exchange} snapshots: {len(pools)} succeeded, {len(self.ignored_pools)} failed"
            )

        return pools

    def decode_pool_state(
        self, snapshot: ComponentWithState, block: EVMBlock
    ) -> ThirdPartyPool:
        component = snapshot.component
        state_attributes = snapshot.state.attributes
        static_attributes = component.static_attributes

        tokens = [t.hex() for t in component.tokens]
        try:
            tokens = self.token_factory_func(tokens)
        except KeyError as e:
            raise TychoDecodeError(f"Unsupported token: {e}", pool_id=component.id)

        balances = self.decode_balances(snapshot.state.balances, tokens)

        optional_attributes = self.decode_optional_attributes({**state_attributes, **static_attributes})
        pool_id = component.id
        if "pool_id" in static_attributes:
            pool_id = static_attributes.pop("pool_id").decode("utf-8")
        manual_updates = static_attributes.get("manual_updates", False)

        if not manual_updates:
            # do not trigger pool updates on contract changes for exchanges configured to listen for manual updates
            for address in component.contract_ids:
                self.contract_pools[address.hex()].append(pool_id)

        return ThirdPartyPool(
            id_=pool_id,
            tokens=tokens,
            balances=balances,
            block=block,
            marginal_prices={},
            adapter_contract_path=self.adapter_contract,
            trace=self.trace,
            manual_updates=manual_updates,
            **optional_attributes,
        )

    @staticmethod
    def decode_optional_attributes(attributes):
        # Handle optional state attributes
        balance_owner = attributes.get("balance_owner")
        if balance_owner is not None:
            balance_owner = balance_owner.hex()
        stateless_contracts = {}
        index = 0
        while f"stateless_contract_addr_{index}" in attributes:
            encoded_address = attributes[f"stateless_contract_addr_{index}"].hex()
            # Stateless contracts address must be utf-8 encoded
            decoded = bytes.fromhex(
                encoded_address[2:] if encoded_address.startswith('0x') else encoded_address).decode('utf-8')
            code = (value.hex() if (value := attributes.get(f"stateless_contract_code_{index}")) is not None else None)
            stateless_contracts[decoded] = code
            index += 1
        return {
            "balance_owner": balance_owner,
            "stateless_contracts": stateless_contracts,
        }

    @staticmethod
    def decode_balances(
        balances_msg: dict[HexBytes, HexBytes], tokens: list[EthereumToken]
    ):
        balances = {}
        for addr, balance in balances_msg.items():
            checksum_addr = to_checksum_address(addr)
            token = next(t for t in tokens if t.address == checksum_addr)
            balances[token.address] = token.from_onchain_amount(
                int(balance)  # balances are big endian encoded
            )
        return balances

    def apply_deltas(
        self, pools: dict[str, ThirdPartyPool], delta_msg: BlockChanges, block: EVMBlock
    ) -> dict[str, ThirdPartyPool]:
        updated_pools = {}

        account_updates = delta_msg.account_updates
        state_updates = delta_msg.state_updates
        balance_updates = delta_msg.component_balances

        # Update contract changes
        vm_updates = self._handle_vm_updates(block, account_updates)

        # add affected pools to update list
        for account in vm_updates:
            for pool_id in self.contract_pools.get(account.address, []):
                pool = pools[pool_id]
                pool.block = block
                updated_pools[pool_id] = pool

        # Update balances
        for component_id, balance_update in balance_updates.items():
            pool_id = self.component_pool_id.get(component_id, component_id)
            pool = pools[pool_id]
            for addr, token_balance in balance_update.items():
                checksum_addr = to_checksum_address(addr)
                token = next(t for t in pool.tokens if t.address == checksum_addr)
                balance = token.from_onchain_amount(
                    int.from_bytes(token_balance.balance, "big", signed=False)
                )  # balances are big endian encoded
                pool.balances[token.address] = balance
            pool.block = block
            updated_pools[pool_id] = pool

        # Update state attributes
        for component_id, pool_update in state_updates.items():
            pool_id = self.component_pool_id.get(component_id, component_id)
            pool = updated_pools.get(pool_id) or pools[pool_id]

            attributes = pool_update.get("updated_attributes")
            if "balance_owner" in attributes:
                pool.balance_owner = attributes["balance_owner"]
            # TODO: handle stateless_contracts updates
            pool.block = block

            if not pool.manual_attributes or attributes.get("update_marker", False):
                # NOTE - the "update_marker" attribute is used to trigger recalculation of spot prices ect. on
                # protocols with custom update rules (i.e. core contract changes only trigger updates on certain pools
                # ect). This allows us to skip unnecessary simulations when the deltas do not affect prices.
                pool.clear_all_cache()

            updated_pools[pool_id] = pool

        return updated_pools

    def _handle_vm_updates(
        self,
        block,
        account_updates: Union[
            dict[dto.HexBytes, dto.AccountUpdate],
            dict[dto.HexBytes, dto.ResponseAccount],
        ],
    ) -> list[AccountUpdate]:
        vm_updates = []
        for address, account_update in account_updates.items():
            # collect contract updates to apply to simulation db
            slots = {int(k): int(v) for k, v in account_update.slots.items()}
            balance = account_update.balance
            code = account_update.code
            change = account_update.change.value

            vm_updates.append(
                AccountUpdate(
                    address=address.hex(),
                    chain=account_update.chain,
                    slots=slots,
                    balance=int(balance) if balance is not None else None,
                    code=bytearray(code) if code is not None else None,
                    change=account_update.change,
                )
            )
        if vm_updates:
            # apply updates to simulation db
            db = TychoDBSingleton.get_instance()
            block_header = BlockHeader(block.id, block.hash_, int(block.ts.timestamp()))
            db.update(vm_updates, block_header)
        return vm_updates
