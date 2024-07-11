import asyncio
import json
import platform
import time
from asyncio.subprocess import STDOUT, PIPE
from collections import defaultdict
from datetime import datetime
from decimal import Decimal
from logging import getLogger
from typing import Tuple, Any, Optional

from eth_utils import to_checksum_address
from protosim_py import (
    AccountUpdate,
    AccountInfo,
    BlockHeader,
    TychoDB,
    SimulationEngine,
)

from tycho.tycho.constants import (
    TYCHO_CLIENT_LOG_FOLDER,
    TYCHO_CLIENT_FOLDER,
    EXTERNAL_ACCOUNT,
    MAX_BALANCE,
)
from tycho.tycho.decoders import ThirdPartyPoolTychoDecoder
from tycho.tycho.models import Blockchain, EVMBlock, ThirdPartyPool

log = getLogger(__name__)


class TychoClientException(Exception):
    pass


class TychoPoolStateStreamAdapter:
    def __init__(
        self,
        tycho_url: str,
        protocol: str,
        blockchain: Blockchain,
        min_tvl: Optional[Decimal] = 10,
        min_token_quality: Optional[int] = 51,
        include_state=True,
    ):
        """
        :param tycho_url: URL to connect to Tycho DB
        :param protocol: Name of the protocol that you're testing
        :param blockchain: Blockchain enum
        :param min_tvl: Minimum TVL to consider a pool
        :param min_token_quality: Minimum token quality to consider a token
        :param include_state: Include state in the stream
        """
        self.min_token_quality = min_token_quality
        self.tycho_url = tycho_url
        self.min_tvl = min_tvl
        self.tycho_client = None
        self.protocol = "vm:protocol"
        self._include_state = include_state
        self._blockchain = blockchain

        # Create engine
        self._db = TychoDB(tycho_http_url=self.tycho_url)
        self._engine = SimulationEngine.new_with_tycho_db(db=self._db, trace=True)
        self._engine.init_account(
            address=EXTERNAL_ACCOUNT,
            account=AccountInfo(balance=MAX_BALANCE, nonce=0, code=None),
            mocked=False,
            permanent_storage=None,
        )

        # TODO: Check if it's necessary
        self.ignored_pools = []
        self.vm_contracts = defaultdict(list)

    async def start(self):
        """Start the tycho-client Rust binary through subprocess"""
        # stdout=PIPE means that the output is piped directly to this Python process
        # stderr=STDOUT combines the stderr and stdout streams
        bin_path = self._get_binary_path()

        cmd = [
            "--log-folder",
            TYCHO_CLIENT_LOG_FOLDER,
            "--tycho-url",
            self.tycho_url,
            "--min-tvl",
            self.min_tvl,
        ]
        if not self._include_state:
            cmd.append("--no-state")
        cmd.append("--exchange")
        cmd.append(self.protocol)

        log.debug(f"Starting tycho-client binary at {bin_path}. CMD: {cmd}")
        self.tycho_client = await asyncio.create_subprocess_exec(
            bin_path, *cmd, stdout=PIPE, stderr=STDOUT, limit=2 ** 64
        )

    @staticmethod
    def _get_binary_path():
        """Determines the correct binary path based on the OS and architecture."""
        os_name = platform.system()
        if os_name == "Linux":
            architecture = platform.machine()
            if architecture == "aarch64":
                return TYCHO_CLIENT_FOLDER / "tycho-client-linux-arm64"
            else:
                return TYCHO_CLIENT_FOLDER / "tycho-client-linux-x64"
        elif os_name == "Darwin":
            architecture = platform.machine()
            if architecture == "arm64":
                return TYCHO_CLIENT_FOLDER / "tycho-client-mac-arm64"
            else:
                return TYCHO_CLIENT_FOLDER / "tycho-client-mac-x64"
        else:
            raise ValueError(f"Unsupported OS: {os_name}")

    def __aiter__(self):
        return self

    async def __anext__(self) -> BlockProtocolChanges:
        if self.tycho_client.stdout.at_eof():
            raise StopAsyncIteration
        line = await self.tycho_client.stdout.readline()

        try:
            if not line:
                exit_code = await self.tycho_client.wait()
                if exit_code == 0:
                    # Clean exit, handle accordingly, possibly without raising an error
                    log.debug("Tycho client exited cleanly.")
                    raise StopAsyncIteration
                else:
                    line = f"Tycho client failed with exit code: {exit_code}"
                    # Non-zero exit code, handle accordingly, possibly by raising an error
                    raise TychoClientException(line)

            msg = json.loads(line.decode("utf-8"))
        except (json.JSONDecodeError, TychoClientException):
            # Read the last 10 lines from the log file available under TYCHO_CLIENT_LOG_FOLDER
            # and raise an exception with the last 10 lines
            error_msg = f"Invalid JSON output on tycho. Original line: {line}."
            with open(TYCHO_CLIENT_LOG_FOLDER / "dev_logs.log", "r") as f:
                lines = f.readlines()
                last_lines = lines[-10:]
                error_msg += f" Tycho logs: {last_lines}"
            log.exception(error_msg)
            raise Exception("Tycho-client failed.")
        return self._process_message(msg)

    def _process_message(self, msg) -> BlockProtocolChanges:
        try:
            sync_state = msg["sync_states"][self.protocol]
            state_msg = msg["state_msgs"][self.protocol]
            log.info(f"Received sync state for {self.protocol}: {sync_state}")
            if not sync_state["status"] != "ready":
                raise ValueError("Tycho-indexer is not synced")
        except KeyError:
            raise ValueError("Invalid message received from tycho-client.")

        start = time.monotonic()

        removed_pools = set()
        decoded_count = 0
        failed_count = 0

        block = EVMBlock(
            id=msg["block"]["id"],
            ts=datetime.fromtimestamp(msg["block"]["timestamp"]),
            hash_=msg["block"]["hash"],
        )

        self._process_vm_storage(state_msg["snapshots"]["vm_storage"], block)

        # decode new pools
        decoded_pools, failed_pools = ThirdPartyPoolTychoDecoder().decode_snapshot(
            state_msg["snapshots"]["states"], block
        )

        decoded_count += len(decoded_pools)
        failed_count += len(failed_pools)

        for addr, p in decoded_pools.items():
            self.vm_contracts[addr].append(p.id_)
        decoded_pools = {
            p.id_: p for p in decoded_pools.values()
        }  # remap pools to their pool ids

        deserialization_time = time.monotonic() - start

        total = decoded_count + failed_count
        log.debug(
            f"Received {total} snapshots. n_decoded: {decoded_count}, n_failed: {failed_count}"
        )
        if failed_count > 0:
            log.info(f"Could not to decode {failed_count}/{total} pool snapshots")

        return BlockProtocolChanges(
            block=self.current_block,
            pool_states=pool_states,
            removed_pools=removed_pools,
            sync_states=exchanges_states,
            deserialization_time=round(deserialization_time, 3),
        )

    def _process_vm_storage(self, storage: dict[str, Any], block: EVMBlock):
        vm_updates = []
        for storage_update in storage.values():
            address = storage_update["address"]
            balance = int(storage_update["native_balance"], 16)
            code = bytearray.fromhex(storage_update["code"][2:])

            # init accounts
            self._engine.init_account(
                address=address,
                account=AccountInfo(balance=balance, nonce=0, code=code),
                mocked=False,
                permanent_storage=None,
            )

            # apply account updates
            slots = {int(k, 16): int(v, 16) for k, v in storage_update["slots"].items()}
            vm_updates.append(
                AccountUpdate(
                    address=address,
                    chain=storage_update["chain"],
                    slots=slots,
                    balance=balance,
                    code=code,
                    change="Update",
                )
            )

        block_header = BlockHeader(block.id, block.hash_, int(block.ts.timestamp()))
        self._db.update(vm_updates, block_header)
