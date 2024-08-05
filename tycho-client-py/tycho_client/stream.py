import asyncio
import json
import os
import platform
import shutil

from decimal import Decimal
from logging import getLogger
from pathlib import Path
from subprocess import PIPE, STDOUT
from typing import Any

from pydantic import ValidationError

from .dto import Chain, FeedMessage
from .exception import TychoStreamException

log = getLogger(__name__)


class TychoStream:
    def __init__(
        self,
        tycho_url: str,
        exchanges: list[str],
        min_tvl: Decimal,
        blockchain: Chain,
        include_state=True,
        logs_directory: str = None,
        tycho_client_path: str = None,
    ):
        self.tycho_url = tycho_url
        self.min_tvl = min_tvl
        self.tycho_client = None
        self.exchanges = exchanges
        self._include_state = include_state
        self._blockchain = blockchain
        self._logs_directory = logs_directory or get_default_log_directory()
        self._tycho_client_path = tycho_client_path or find_tycho_client()

    async def start(self):
        """Start the tycho-client Rust binary through subprocess"""
        # stdout=PIPE means that the output is piped directly to this Python process
        # stderr=STDOUT combines the stderr and stdout streams

        cmd = [
            "--log-folder",
            self._logs_directory,
            "--tycho-url",
            self.tycho_url,
            "--min-tvl",
            str(self.min_tvl),
        ]
        if not self._include_state:
            cmd.append("--no-state")
        for exchange in self.exchanges:
            cmd.append("--exchange")
            cmd.append(exchange)

        log.debug(
            f"Starting tycho-client binary at {self._tycho_client_path}. CMD: {cmd}"
        )
        self.tycho_client = await asyncio.create_subprocess_exec(
            self._tycho_client_path, *cmd, stdout=PIPE, stderr=STDOUT, limit=2**64
        )

    def __aiter__(self):
        return self

    async def __anext__(self) -> FeedMessage:
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
                    raise TychoStreamException(line)

            msg = json.loads(line.decode("utf-8"))
        except (json.JSONDecodeError, TychoStreamException):
            # Read the last 10 lines from the log file available under TYCHO_CLIENT_LOG_FOLDER
            # and raise an exception with the last 10 lines
            error_msg = f"Invalid JSON output on tycho. Original line: {line}."
            with open(Path(self._logs_directory) / "dev_logs.log", "r") as f:
                lines = f.readlines()
                last_lines = lines[-10:]
                error_msg += f" Tycho logs: {last_lines}"
            log.exception(error_msg)
            raise Exception("Tycho-client failed.")
        return self._process_message(msg)

    @staticmethod
    def _process_message(msg: dict[str, Any]) -> FeedMessage:
        try:
            return FeedMessage(**msg)
        except ValidationError:
            print(json.dumps(msg, indent=2))
            raise


def get_default_log_directory():
    system = platform.system()

    if system == "Windows":
        default_dir = os.path.join(os.getenv("APPDATA"), "tycho-client", "logs")
    elif system == "Darwin":  # macOS
        default_dir = os.path.join(
            os.path.expanduser("~"), "Library", "Logs", "tycho-client"
        )
    else:  # Linux and other Unix-like systems
        default_dir = os.path.join(
            os.path.expanduser("~"), ".local", "share", "tycho-client", "logs"
        )

    # Create the directory if it doesn't exist
    os.makedirs(default_dir, exist_ok=True)

    return default_dir


def find_tycho_client():
    # Check if 'tycho-client' is in the PATH
    tycho_client_path = shutil.which("tycho-client")

    return tycho_client_path


if __name__ == "__main__":
    stream = TychoStream("localhost:8888", ["uniswap_v2"], Decimal(100), Chain.ethereum)

    async def print_messages():
        await stream.start()
        async for msg in stream:
            print(msg)

    asyncio.run(print_messages())
