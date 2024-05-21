import os
from pathlib import Path
import shutil
import subprocess

import yaml

from evm import get_token_balance
from tycho import TychoRunner


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


class TestRunner:
    def __init__(self, config_path: str, with_binary_logs: bool):
        self.config = load_config(config_path)
        self.base_dir = os.path.dirname(config_path)
        self.tycho_runner = TychoRunner(with_binary_logs)

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

            self.tycho_runner.empty_database(
                "postgres://postgres:mypassword@localhost:5432"
            )

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
                for state in protocol_states["states"]:
                    for token, balance in state["balances"].items():
                        node_balance = get_token_balance(token,comp_id,stop_block)
                        tycho_balance = int(balance,16)
                        if node_balance != tycho_balance:
                            return TestResult.Failed(f"Balance mismatch for {comp_id}:{token} at block {stop_block}: got {node_balance} from rpc call and {tycho_balance} from Substreams")
            return TestResult.Passed()

        except Exception as e:
            return TestResult.Failed(str(e))

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
