import asyncio
import json
import platform
import time
from asyncio.subprocess import STDOUT, PIPE
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from http.client import HTTPException
from logging import getLogger
from typing import Any, Optional, Dict

import requests
from protosim_py import AccountUpdate, AccountInfo, BlockHeader

from .pool_state import ThirdPartyPool
from .constants import TYCHO_CLIENT_LOG_FOLDER, TYCHO_CLIENT_FOLDER
from .decoders import ThirdPartyPoolTychoDecoder
from .exceptions import APIRequestError, TychoClientException
from .models import Blockchain, EVMBlock, EthereumToken, SynchronizerState, Address
from .tycho_db import TychoDBSingleton
from .utils import create_engine

log = getLogger(__name__)


class TokenLoader:
    def __init__(
        self,
        tycho_url: str,
        blockchain: Blockchain,
        min_token_quality: Optional[int] = 0,
    ):
        self.tycho_url = tycho_url
        self.blockchain = blockchain
        self.min_token_quality = min_token_quality
        self.endpoint = "/v1/{}/tokens"
        self._token_limit = 10000

    def get_tokens(self) -> dict[str, EthereumToken]:
        """Loads all tokens from Tycho RPC"""
        url = self.tycho_url + self.endpoint.format(self.blockchain.value)
        page = 0

        start = time.monotonic()
        all_tokens = []
        while data := self._get_all_with_pagination(
            url=url,
            page=page,
            limit=self._token_limit,
            params={"min_quality": self.min_token_quality},
        ):
            all_tokens.extend(data)
            page += 1
            if len(data) < self._token_limit:
                break

        log.info(f"Loaded {len(all_tokens)} tokens in {time.monotonic() - start:.2f}s")

        formatted_tokens = dict()

        for token in all_tokens:
            formatted = EthereumToken(**token)
            formatted_tokens[formatted.address] = formatted

        return formatted_tokens

    def get_token_subset(self, addresses: list[str]) -> dict[str, EthereumToken]:
        """Loads a subset of tokens from Tycho RPC"""
        url = self.tycho_url + self.endpoint.format(self.blockchain.value)
        page = 0

        start = time.monotonic()
        all_tokens = []
        while data := self._get_all_with_pagination(
            url=url,
            page=page,
            limit=self._token_limit,
            params={"min_quality": self.min_token_quality, "addresses": addresses},
        ):
            all_tokens.extend(data)
            page += 1
            if len(data) < self._token_limit:
                break

        log.info(f"Loaded {len(all_tokens)} tokens in {time.monotonic() - start:.2f}s")

        formatted_tokens = dict()

        for token in all_tokens:
            formatted = EthereumToken(**token)
            formatted_tokens[formatted.address] = formatted

        return formatted_tokens

    @staticmethod
    def _get_all_with_pagination(
        url: str, params: Optional[Dict] = None, page: int = 0, limit: int = 50
    ) -> Dict:
        if params is None:
            params = {}

        params["pagination"] = {"page": page, "page_size": limit}
        r = requests.post(url, json=params)
        try:
            r.raise_for_status()
        except HTTPException as e:
            log.error(f"Request status {r.status_code} with content {r.json()}")
            raise APIRequestError("Failed to load token configurations")
        return r.json()["tokens"]


@dataclass(repr=False)
class BlockProtocolChanges:
    block: EVMBlock
    pool_states: dict[Address, ThirdPartyPool]
    """All updated pools"""
    removed_pools: set[Address]
    sync_states: dict[str, SynchronizerState]
    deserialization_time: float
    """The time it took to deserialize the pool states from the tycho feed message"""


class TychoPoolStateStreamAdapter:
    def __init__(
        self,
        tycho_url: str,
        protocol: str,
        decoder: ThirdPartyPoolTychoDecoder,
        blockchain: Blockchain,
        min_tvl: Optional[Decimal] = 10,
        min_token_quality: Optional[int] = 0,
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
        self.protocol = f"vm:{protocol}"
        self._include_state = include_state
        self._blockchain = blockchain
        self._decoder = decoder

        # Create engine
        # TODO: This should be initialized outside the adapter?
        TychoDBSingleton.initialize(tycho_http_url=self.tycho_url)
        self._engine = create_engine([], trace=True)

        # Loads tokens from Tycho
        self._tokens: dict[str, EthereumToken] = TokenLoader(
            tycho_url=f"http://{self.tycho_url}",
            blockchain=self._blockchain,
            min_token_quality=self.min_token_quality,
        ).get_tokens()

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
            str(TYCHO_CLIENT_LOG_FOLDER),
            "--tycho-url",
            self.tycho_url,
            "--min-tvl",
            str(self.min_tvl),
        ]
        if not self._include_state:
            cmd.append("--no-state")
        cmd.append("--exchange")
        cmd.append(self.protocol)

        log.debug(f"Starting tycho-client binary at {bin_path}. CMD: {cmd}")
        self.tycho_client = await asyncio.create_subprocess_exec(
            str(bin_path), *cmd, stdout=PIPE, stderr=STDOUT, limit=2 ** 64
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
            if not sync_state["status"] != SynchronizerState.ready.value:
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
        decoded_pools, failed_pools = self._decoder.decode_snapshot(
            state_msg["snapshots"]["states"], block, self._tokens
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
            block=block,
            pool_states=decoded_pools,
            removed_pools=removed_pools,
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
