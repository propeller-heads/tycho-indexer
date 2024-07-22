import os
import platform
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import psycopg2
import requests
from psycopg2 import sql


def get_binary_path():
    path = Path(__file__).parent
    if sys.platform.startswith("darwin") and platform.machine() == "arm64":
        return Path(__file__).parent / "tycho-indexer-mac-arm64"
    elif sys.platform.startswith("linux") and platform.machine() == "x86_64":
        return Path(__file__).parent / "tycho-indexer-linux-x64"

    else:
        raise RuntimeError("Unsupported platform or architecture")


binary_path = get_binary_path()


class TychoRPCClient:
    def __init__(self, rpc_url: str = "http://0.0.0.0:4242"):
        self.rpc_url = rpc_url

    def get_protocol_components(self) -> dict:
        """Retrieve protocol components from the RPC server."""
        url = self.rpc_url + "/v1/ethereum/protocol_components"
        headers = {"accept": "application/json", "Content-Type": "application/json"}
        data = {"protocol_system": "test_protocol"}

        response = requests.post(url, headers=headers, json=data)
        return response.json()

    def get_protocol_state(self) -> dict:
        """Retrieve protocol state from the RPC server."""
        url = self.rpc_url + "/v1/ethereum/protocol_state"
        headers = {"accept": "application/json", "Content-Type": "application/json"}
        data = {}

        response = requests.post(url, headers=headers, json=data)
        return response.json()

    def get_contract_state(self) -> dict:
        """Retrieve contract state from the RPC server."""
        url = self.rpc_url + "/v1/ethereum/contract_state"
        headers = {"accept": "application/json", "Content-Type": "application/json"}
        data = {}

        response = requests.post(url, headers=headers, json=data)
        return response.json()


class TychoRunner:
    def __init__(self, with_binary_logs: bool = False):
        self.with_binary_logs = with_binary_logs

    def run_tycho(
        self,
        spkg_path: str,
        start_block: int,
        end_block: int,
        protocol_type_names: list,
    ) -> None:
        """Run the Tycho indexer with the specified SPKG and block range."""

        env = os.environ.copy()
        env["RUST_LOG"] = "info"

        try:
            process = subprocess.Popen(
                [
                    binary_path,
                    "run",
                    "--spkg",
                    spkg_path,
                    "--module",
                    "map_protocol_changes",
                    "--protocol-type-names",
                    ",".join(protocol_type_names),
                    "--start-block",
                    str(start_block),
                    "--stop-block",
                    str(end_block + 2),
                ],  # +2 is to make up for the cache in the index side.
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=env,
            )

            with process.stdout:
                for line in iter(process.stdout.readline, ""):
                    if line and self.with_binary_logs:
                        print(line.strip())

            with process.stderr:
                for line in iter(process.stderr.readline, ""):
                    if line and self.with_binary_logs:
                        print(line.strip())

            process.wait()

        except Exception as e:
            print(f"Error running Tycho indexer: {e}")

    def run_with_rpc_server(self, func: callable, *args, **kwargs):
        """
        Run a function with Tycho RPC running in background.

        This function is a wrapper around a target function. It starts Tycho RPC as a background task, executes the target function and stops Tycho RPC.
        """
        stop_event = threading.Event()
        process = None

        def run_rpc_server():
            nonlocal process
            try:
                env = os.environ.copy()
                env["RUST_LOG"] = "info"

                process = subprocess.Popen(
                    [binary_path, "rpc"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    env=env,
                )
                # Read remaining stdout and stderr
                if self.with_binary_logs:
                    for output in process.stdout:
                        if output:
                            print(output.strip())

                    for error_output in process.stderr:
                        if error_output:
                            print(error_output.strip())

                process.wait()

                if process.returncode != 0:
                    print("Command failed with return code:", process.returncode)

            except Exception as e:
                print(f"An error occurred while running the command: {e}")
            finally:
                if process and process.poll() is None:
                    process.terminate()
                    process.wait()

        # Start the RPC server in a separate thread
        rpc_thread = threading.Thread(target=run_rpc_server)
        rpc_thread.start()
        time.sleep(3)  # Wait for the RPC server to start

        try:
            # Run the provided function
            result = func(*args, **kwargs)
            return result

        finally:
            stop_event.set()
            if process and process.poll() is None:
                process.send_signal(signal.SIGINT)
            if rpc_thread.is_alive():
                rpc_thread.join()

    @staticmethod
    def empty_database(db_url: str) -> None:
        """Drop and recreate the Tycho indexer database."""
        try:
            conn = psycopg2.connect(db_url)
            conn.autocommit = True
            cursor = conn.cursor()

            cursor.execute(
                sql.SQL("DROP DATABASE IF EXISTS {}").format(
                    sql.Identifier("tycho_indexer_0")
                )
            )
            cursor.execute(
                sql.SQL("CREATE DATABASE {}").format(sql.Identifier("tycho_indexer_0"))
            )

        except psycopg2.Error as e:
            print(f"Database error: {e}")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
