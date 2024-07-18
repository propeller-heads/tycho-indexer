import itertools
import itertools
import os
import shutil
import subprocess
from collections import defaultdict
from datetime import datetime
from decimal import Decimal
from pathlib import Path

import yaml
from pydantic import BaseModel

from evm import get_token_balance, get_block_header
from tycho import TychoRunner
from tycho_client.tycho.decoders import ThirdPartyPoolTychoDecoder
from tycho_client.tycho.models import Blockchain, EVMBlock
from tycho_client.tycho.tycho_adapter import (
    TychoPoolStateStreamAdapter,
)


class TestResult:
    def __init__(self, success: bool, message: str = None):
        self.success = success
        self.message = message

    @classmethod
    def Passed(cls):
        return cls(success=True)

    @classmethod
    def Failed(cls, message: str):
        return cls(success=False, message=message)


def load_config(yaml_path: str) -> dict:
    """Load YAML configuration from a specified file path."""
    with open(yaml_path, "r") as file:
        return yaml.safe_load(file)


class SimulationFailure(BaseModel):
    pool_id: str
    sell_token: str
    buy_token: str
    error: str


class TestRunner:
    def __init__(self, config_path: str, with_binary_logs: bool, db_url: str):
        self.config = load_config(config_path)
        self.base_dir = os.path.dirname(config_path)
        self.tycho_runner = TychoRunner(with_binary_logs)
        self.db_url = db_url
        self._chain = Blockchain.ethereum

    def run_tests(self) -> None:
        """Run all tests specified in the configuration."""
        print(f"Running tests ...")
        for test in self.config["tests"]:

            spkg_path = self.build_spkg(
                os.path.join(self.base_dir, self.config["substreams_yaml_path"]),
                lambda data: self.update_initial_block(data, test["start_block"]),
            )
            self.tycho_runner.run_tycho(
                spkg_path,
                test["start_block"],
                test["stop_block"],
                self.config["protocol_type_names"],
            )

            result = self.tycho_runner.run_with_rpc_server(
                self.validate_state, test["expected_state"], test["stop_block"]
            )

            if result.success:
                print(f"✅ {test['name']} passed.")

            else:
                print(f"❗️ {test['name']} failed: {result.message}")

            self.tycho_runner.empty_database(self.db_url)

    def validate_state(self, expected_state: dict, stop_block: int) -> TestResult:
        """Validate the current protocol state against the expected state."""
        protocol_components = self.tycho_runner.get_protocol_components()
        protocol_states = self.tycho_runner.get_protocol_state()
        components = {
            component["id"]: component
            for component in protocol_components["protocol_components"]
        }

        try:
            for expected_component in expected_state.get("protocol_components", []):
                comp_id = expected_component["id"].lower()
                if comp_id not in components:
                    return TestResult.Failed(
                        f"'{comp_id}' not found in protocol components."
                    )

                component = components[comp_id]
                for key, value in expected_component.items():
                    if key not in component:
                        return TestResult.Failed(
                            f"Missing '{key}' in component '{comp_id}'."
                        )
                    if isinstance(value, list):
                        if set(map(str.lower, value)) != set(
                            map(str.lower, component[key])
                        ):
                            return TestResult.Failed(
                                f"List mismatch for key '{key}': {value} != {component[key]}"
                            )
                    elif value is not None and value.lower() != component[key]:
                        return TestResult.Failed(
                            f"Value mismatch for key '{key}': {value} != {component[key]}"
                        )

            token_balances: dict[str, dict[str, int]] = defaultdict(dict)
            for component in protocol_components["protocol_components"]:
                comp_id = component["id"].lower()
                for token in component["tokens"]:
                    token_lower = token.lower()
                    state = next(
                        (
                            s
                            for s in protocol_states["states"]
                            if s["component_id"].lower() == comp_id
                        ),
                        None,
                    )
                    if state:
                        balance_hex = state["balances"].get(token_lower, "0x0")
                    else:
                        balance_hex = "0x0"
                    tycho_balance = int(balance_hex, 16)
                    token_balances[comp_id][token_lower] = tycho_balance

                    node_balance = get_token_balance(token, comp_id, stop_block)
                    if node_balance != tycho_balance:
                        return TestResult.Failed(
                            f"Balance mismatch for {comp_id}:{token} at block {stop_block}: got {node_balance} from rpc call and {tycho_balance} from Substreams"
                        )
            contract_states = self.tycho_runner.get_contract_state()
            self.simulate_get_amount_out(
                token_balances,
                stop_block,
                protocol_states,
                protocol_components,
                contract_states,
            )

            return TestResult.Passed()
        except Exception as e:
            return TestResult.Failed(str(e))

    def simulate_get_amount_out(
        self,
        token_balances: dict[str, dict[str, int]],
        block_number: int,
        protocol_states: dict,
        protocol_components: dict,
        contract_state: dict,
    ) -> TestResult:
        protocol_type_names = self.config["protocol_type_names"]

        block_header = get_block_header(block_number)
        block: EVMBlock = EVMBlock(
            id=block_number,
            ts=datetime.fromtimestamp(block_header.timestamp),
            hash_=block_header.hash.hex(),
        )

        failed_simulations = dict[str, list[SimulationFailure]]
        for protocol in protocol_type_names:
            # TODO: Parametrize this
            decoder = ThirdPartyPoolTychoDecoder(
                "CurveSwapAdapter.evm.runtime", 0, False
            )
            stream_adapter = TychoPoolStateStreamAdapter(
                tycho_url="0.0.0.0:4242",
                protocol=protocol,
                decoder=decoder,
                blockchain=self._chain,
            )
            snapshot_message = stream_adapter.build_snapshot_message(
                protocol_components, protocol_states, contract_state
            )
            decoded = stream_adapter.process_snapshot(block, snapshot_message)

            for pool_state in decoded.pool_states.values():
                pool_id = pool_state.id_
                protocol_balances = token_balances.get(pool_id)
                if not protocol_balances:
                    raise ValueError(f"Missing balances for pool {pool_id}")
                for sell_token, buy_token in itertools.permutations(
                    pool_state.tokens, 2
                ):
                    try:
                        # Try to sell 0.1% of the protocol balance
                        sell_amount = Decimal("0.001") * sell_token.from_onchain_amount(
                            protocol_balances[sell_token.address]
                        )
                        amount_out, gas_used, _ = pool_state.get_amount_out(
                            sell_token, sell_amount, buy_token
                        )
                        # TODO: Should we validate this with an archive node or RPC reader?
                        print(
                            f"Amount out for {pool_id}: {sell_amount} {sell_token} -> {amount_out} {buy_token} - "
                            f"Gas used: {gas_used}"
                        )
                    except Exception as e:
                        print(
                            f"Error simulating get_amount_out for {pool_id}: {sell_token} -> {buy_token}. "
                            f"Error: {e}"
                        )
                        if pool_id not in failed_simulations:
                            failed_simulations[pool_id] = []
                        failed_simulations[pool_id].append(
                            SimulationFailure(
                                pool_id=pool_id,
                                sell_token=sell_token,
                                buy_token=buy_token,
                                error=str(e),
                            )
                        )
                        continue

    @staticmethod
    def build_spkg(yaml_file_path: str, modify_func: callable) -> str:
        """Build a Substreams package with modifications to the YAML file."""
        backup_file_path = f"{yaml_file_path}.backup"
        shutil.copy(yaml_file_path, backup_file_path)

        with open(yaml_file_path, "r") as file:
            data = yaml.safe_load(file)

        modify_func(data)
        spkg_name = f"{yaml_file_path.rsplit('/', 1)[0]}/{data['package']['name'].replace('_', '-', 1)}-{data['package']['version']}.spkg"

        with open(yaml_file_path, "w") as file:
            yaml.dump(data, file, default_flow_style=False)

        try:
            result = subprocess.run(
                ["substreams", "pack", yaml_file_path], capture_output=True, text=True
            )
            if result.returncode != 0:
                print("Substreams pack command failed:", result.stderr)
        except Exception as e:
            print(f"Error running substreams pack command: {e}")

        shutil.copy(backup_file_path, yaml_file_path)
        Path(backup_file_path).unlink()

        return spkg_name

    @staticmethod
    def update_initial_block(data: dict, start_block: int) -> None:
        """Update the initial block for all modules in the configuration data."""
        for module in data["modules"]:
            module["initialBlock"] = start_block
