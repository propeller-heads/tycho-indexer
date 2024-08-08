import signal
import subprocess
import threading
import time

import psycopg2
from psycopg2 import sql

import os


def find_binary_file(file_name):
    # Define usual locations for binary files in Unix-based systems
    locations = [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
    ]

    # Add user's local bin directory if it exists
    home = os.path.expanduser("~")
    if os.path.exists(home + "/.local/bin"):
        locations.append(home + "/.local/bin")

    # Check each location
    for location in locations:
        potential_path = location + "/" + file_name
        if os.path.exists(potential_path):
            return potential_path

    # If binary is not found in the usual locations, return None
    raise RuntimeError("Unable to locate tycho-indexer binary")


binary_path = find_binary_file("tycho-indexer")


class TychoRunner:
    def __init__(
        self,
        db_url: str,
        with_binary_logs: bool = False,
        initialized_accounts: list[str] = None,
    ):
        self.with_binary_logs = with_binary_logs
        self._db_url = db_url
        self._initialized_accounts = initialized_accounts or []

    def run_tycho(
        self,
        spkg_path: str,
        start_block: int,
        end_block: int,
        protocol_type_names: list,
        initialized_accounts: list,
    ) -> None:
        """Run the Tycho indexer with the specified SPKG and block range."""

        env = os.environ.copy()
        env["RUST_LOG"] = "tycho_indexer=info"

        all_accounts = self._initialized_accounts + initialized_accounts

        try:
            process = subprocess.Popen(
                [
                    binary_path,
                    "--database-url",
                    self._db_url,
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
                    # +2 is to make up for the cache in the index side.
                    str(end_block + 2),
                ]
                + (
                    [
                        "--initialized-accounts",
                        ",".join(all_accounts),
                        "--initialization-block",
                        str(start_block),
                    ]
                    if all_accounts
                    else []
                ),
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
                    [binary_path, "--database-url", self._db_url, "rpc"],
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
            conn = psycopg2.connect(db_url[: db_url.rfind("/")])
            conn.autocommit = True
            cursor = conn.cursor()

            cursor.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(
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
