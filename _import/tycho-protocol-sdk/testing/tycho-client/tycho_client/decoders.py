import time
from decimal import Decimal
from logging import getLogger
from typing import Any

import eth_abi
from eth_utils import keccak
from protosim_py import SimulationEngine, SimulationParameters, AccountInfo

from .constants import EXTERNAL_ACCOUNT
from .exceptions import TychoDecodeError
from .models import EVMBlock, EthereumToken
from .pool_state import ThirdPartyPool
from .tycho_db import TychoDBSingleton
from .utils import decode_tycho_exchange, get_code_for_address

log = getLogger(__name__)


class ThirdPartyPoolTychoDecoder:
    """ThirdPartyPool decoder for protocol messages from the Tycho feed"""

    def __init__(self, adapter_contract: str, minimum_gas: int, trace: bool):
        self.adapter_contract = adapter_contract
        self.minimum_gas = minimum_gas
        self.trace = trace

    def decode_snapshot(
        self,
        snapshot: dict[str, Any],
        block: EVMBlock,
        tokens: dict[str, EthereumToken],
    ) -> tuple[dict[str, ThirdPartyPool], list[str]]:
        pools = {}
        failed_pools = []
        for snap in snapshot.values():
            try:
                pool = self.decode_pool_state(snap, block, tokens)
                pools[pool.id_] = pool
            except TychoDecodeError as e:
                log.error(f"Failed to decode third party snapshot: {e}")
                failed_pools.append(snap["component"]["id"])
                continue

        return pools, failed_pools

    def decode_pool_state(
        self, snap: dict, block: EVMBlock, tokens: dict[str, EthereumToken]
    ) -> ThirdPartyPool:
        component = snap["component"]
        exchange, _ = decode_tycho_exchange(component["protocol_system"])

        try:
            tokens = tuple(tokens[t] for t in component["tokens"])
        except KeyError as e:
            raise TychoDecodeError("Unsupported token", pool_id=component["id"])

        balances = self.decode_balances(snap, tokens)
        optional_attributes = self.decode_optional_attributes(component, snap, block.id)

        return ThirdPartyPool(
            id_=optional_attributes.pop("pool_id", component["id"]),
            tokens=tokens,
            balances=balances,
            block=block,
            spot_prices={},
            trading_fee=Decimal("0"),
            exchange=exchange,
            adapter_contract_name=self.adapter_contract,
            minimum_gas=self.minimum_gas,
            trace=self.trace,
            **optional_attributes,
        )

    @staticmethod
    def decode_optional_attributes(component, snap, block_number):
        # Handle optional state attributes
        attributes = snap["state"]["attributes"]
        balance_owner = attributes.get("balance_owner")
        stateless_contracts = {}
        static_attributes = snap["component"]["static_attributes"]
        pool_id = static_attributes.get("pool_id") or component["id"]

        index = 0
        while f"stateless_contract_addr_{index}" in static_attributes:
            encoded_address = static_attributes[f"stateless_contract_addr_{index}"]
            decoded = bytes.fromhex(
                encoded_address[2:]
                if encoded_address.startswith("0x")
                else encoded_address
            ).decode("utf-8")
            if decoded.startswith("call"):
                address = ThirdPartyPoolTychoDecoder.get_address_from_call(
                    block_number, decoded
                )
            else:
                address = decoded

            code = static_attributes.get(
                f"stateless_contract_code_{index}"
            ) or get_code_for_address(address)
            stateless_contracts[address] = code
            index += 1

        index = 0
        while f"stateless_contract_addr_{index}" in attributes:
            address = attributes[f"stateless_contract_addr_{index}"]
            code = attributes.get(
                f"stateless_contract_code_{index}"
            ) or get_code_for_address(address)
            stateless_contracts[address] = code
            index += 1
        return {
            "balance_owner": balance_owner,
            "pool_id": pool_id,
            "stateless_contracts": stateless_contracts,
        }

    @staticmethod
    def get_address_from_call(block_number, decoded):
        db = TychoDBSingleton.get_instance()
        engine = SimulationEngine.new_with_tycho_db(db=db)
        engine.init_account(
            address="0x0000000000000000000000000000000000000000",
            account=AccountInfo(balance=0, nonce=0),
            mocked=False,
            permanent_storage=None,
        )
        selector = keccak(text=decoded.split(":")[-1])[:4]
        sim_result = engine.run_sim(
            SimulationParameters(
                data=bytearray(selector),
                to=decoded.split(":")[1],
                block_number=block_number,
                timestamp=int(time.time()),
                overrides={},
                caller=EXTERNAL_ACCOUNT,
                value=0,
            )
        )
        address = eth_abi.decode(["address"], bytearray(sim_result.result))
        return address[0]

    @staticmethod
    def decode_balances(snap, tokens):
        balances = {}
        for addr, balance in snap["state"]["balances"].items():
            checksum_addr = addr
            token = next(t for t in tokens if t.address == checksum_addr)
            balances[token.address] = token.from_onchain_amount(
                int(balance, 16)  # balances are big endian encoded
            )
        return balances

    @staticmethod
    def apply_update(
        pool: ThirdPartyPool,
        pool_update: dict[str, Any],
        balance_updates: dict[str, Any],
        block: EVMBlock,
    ) -> ThirdPartyPool:
        # check for and apply optional state attributes
        attributes = pool_update.get("updated_attributes")
        if attributes:
            # TODO: handle balance_owner and stateless_contracts updates
            pass

        for addr, balance_msg in balance_updates.items():
            token = [t for t in pool.tokens if t.address == addr][0]
            balance = int(balance_msg["balance"], 16)  # balances are big endian encoded
            pool.balances[token.address] = token.from_onchain_amount(balance)
        pool.block = block
        # we clear simulation cache and overwrites on the pool and trigger a recalculation of spot prices
        pool.clear_all_cache()
        return pool
