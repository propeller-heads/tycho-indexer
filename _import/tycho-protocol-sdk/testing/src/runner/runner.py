import itertools
import os
import shutil
import subprocess
import traceback
from collections import defaultdict
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import List

import yaml
from protosim_py.evm.decoders import ThirdPartyPoolTychoDecoder
from protosim_py.evm.storage import TychoDBSingleton
from protosim_py.models import EVMBlock
from pydantic import BaseModel
from tycho_client.dto import (
    Chain,
    ProtocolComponentsParams,
    ProtocolStateParams,
    ContractStateParams,
    ProtocolComponent,
    ResponseProtocolState,
    HexBytes,
    ResponseAccount,
    Snapshot,
    ContractId,
)
from tycho_client.rpc_client import TychoRPCClient

from models import (
    IntegrationTestsConfig,
    ProtocolComponentWithTestConfig,
    ProtocolComponentExpectation,
)
from adapter_builder import AdapterContractBuilder
from evm import get_token_balance, get_block_header
from tycho import TychoRunner
from utils import build_snapshot_message, token_factory


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


def parse_config(yaml_path: str) -> IntegrationTestsConfig:
    with open(yaml_path, "r") as file:
        yaml_content = yaml.safe_load(file)
    return IntegrationTestsConfig(**yaml_content)


class SimulationFailure(BaseModel):
    pool_id: str
    sell_token: str
    buy_token: str
    error: str


class TestRunner:
    def __init__(
        self, package: str, with_binary_logs: bool, db_url: str, vm_traces: bool
    ):
        self.repo_root = os.getcwd()
        config_path = os.path.join(
            self.repo_root, "substreams", package, "integration_test.tycho.yaml"
        )
        self.config: IntegrationTestsConfig = parse_config(config_path)
        self.spkg_src = os.path.join(self.repo_root, "substreams", package)
        self.adapter_contract_builder = AdapterContractBuilder(
            os.path.join(self.repo_root, "evm")
        )
        self.tycho_runner = TychoRunner(
            db_url, with_binary_logs, self.config.initialized_accounts
        )
        self.tycho_rpc_client = TychoRPCClient()
        self._token_factory_func = token_factory(self.tycho_rpc_client)
        self.db_url = db_url
        self._vm_traces = vm_traces
        self._chain = Chain.ethereum

    def run_tests(self) -> None:
        """Run all tests specified in the configuration."""
        print(f"Running tests ...")

        failed_tests = []

        for test in self.config.tests:
            self.tycho_runner.empty_database(self.db_url)

            spkg_path = self.build_spkg(
                os.path.join(self.spkg_src, self.config.substreams_yaml_path),
                lambda data: self.update_initial_block(data, test.start_block),
            )
            self.tycho_runner.run_tycho(
                spkg_path,
                test.start_block,
                test.stop_block,
                self.config.protocol_type_names,
                test.initialized_accounts or [],
            )

            result = self.tycho_runner.run_with_rpc_server(
                self.validate_state, test.expected_components, test.stop_block
            )

            if result.success:
                print(f"\n✅ {test.name} passed.\n")
            else:
                print(f"\n❗️ {test.name} failed: {result.message}\n")

        print(
            "\nTest finished! \n"
            f"Passed: {len(self.config.tests) - len(failed_tests)}/{len(self.config.tests)}\n"
        )
        if failed_tests:
            print("Failed tests:")
            for failed_test in failed_tests:
                print(failed_test)

    def validate_state(
        self,
        expected_components: List[ProtocolComponentWithTestConfig],
        stop_block: int,
    ) -> TestResult:
        """Validate the current protocol state against the expected state."""
        protocol_components = self.tycho_rpc_client.get_protocol_components(
            ProtocolComponentsParams(protocol_system="test_protocol")
        )
        protocol_states = self.tycho_rpc_client.get_protocol_state(
            ProtocolStateParams(protocol_system="test_protocol")
        )
        components_by_id = {
            component.id: component for component in protocol_components
        }

        try:
            for expected_component in expected_components:
                comp_id = expected_component.id.lower()
                if comp_id not in components_by_id:
                    return TestResult.Failed(
                        f"'{comp_id}' not found in protocol components."
                    )

                diff = ProtocolComponentExpectation(
                    **components_by_id[comp_id].dict()
                ).compare(ProtocolComponentExpectation(**expected_component.dict()))
                if diff is not None:
                    return TestResult.Failed(diff)

            token_balances: dict[str, dict[HexBytes, int]] = defaultdict(dict)
            for component in protocol_components:
                comp_id = component.id.lower()
                for token in component.tokens:
                    state = next(
                        (
                            s
                            for s in protocol_states
                            if s.component_id.lower() == comp_id
                        ),
                        None,
                    )
                    if state:
                        balance_hex = state.balances.get(token, HexBytes("0x00"))
                    else:
                        balance_hex = HexBytes("0x00")
                    tycho_balance = int(balance_hex)
                    token_balances[comp_id][token] = tycho_balance

                    if not self.config.skip_balance_check:
                        node_balance = get_token_balance(token, comp_id, stop_block)
                        if node_balance != tycho_balance:
                            return TestResult.Failed(
                                f"Balance mismatch for {comp_id}:{token} at block {stop_block}: got {node_balance} "
                                f"from rpc call and {tycho_balance} from Substreams"
                            )
            contract_states = self.tycho_rpc_client.get_contract_state(
                ContractStateParams(
                    contract_ids=[
                        ContractId(chain=self._chain, address=a)
                        for component in protocol_components
                        for a in component.contract_ids
                    ]
                )
            )
            filtered_components = [
                pc
                for pc in protocol_components
                if pc.id
                in [c.id for c in expected_components if c.skip_simulation is False]
            ]
            simulation_failures = self.simulate_get_amount_out(
                stop_block, protocol_states, filtered_components, contract_states
            )
            if len(simulation_failures):
                error_msgs = []
                for pool_id, failures in simulation_failures.items():
                    failures_ = [
                        f"{f.sell_token} -> {f.buy_token}: {f.error}" for f in failures
                    ]
                    error_msgs.append(
                        f"Pool {pool_id} failed simulations: {', '.join(failures_)}"
                    )
                raise ValueError(". ".join(error_msgs))

            return TestResult.Passed()
        except Exception as e:
            error_message = f"An error occurred: {str(e)}\n" + traceback.format_exc()
            return TestResult.Failed(error_message)

    def simulate_get_amount_out(
        self,
        block_number: int,
        protocol_states: list[ResponseProtocolState],
        protocol_components: list[ProtocolComponent],
        contract_states: list[ResponseAccount],
    ) -> dict[str, list[SimulationFailure]]:
        TychoDBSingleton.initialize()
        protocol_type_names = self.config.protocol_type_names

        block_header = get_block_header(block_number)
        block: EVMBlock = EVMBlock(
            id=block_number,
            ts=datetime.fromtimestamp(block_header.timestamp),
            hash_=block_header.hash.hex(),
        )

        failed_simulations: dict[str, list[SimulationFailure]] = dict()

        try:
            adapter_contract = self.adapter_contract_builder.find_contract(
                self.config.adapter_contract
            )
        except FileNotFoundError:
            adapter_contract = self.adapter_contract_builder.build_target(
                self.config.adapter_contract,
                self.config.adapter_build_signature,
                self.config.adapter_build_args,
            )

        decoder = ThirdPartyPoolTychoDecoder(
            token_factory_func=self._token_factory_func,
            adapter_contract=adapter_contract,
            minimum_gas=0,
            trace=self._vm_traces,
        )

        snapshot_message: Snapshot = build_snapshot_message(
            protocol_states, protocol_components, contract_states
        )

        decoded = decoder.decode_snapshot(snapshot_message, block)

        for pool_state in decoded.values():
            pool_id = pool_state.id_
            if not pool_state.balances:
                raise ValueError(f"Missing balances for pool {pool_id}")
            for sell_token, buy_token in itertools.permutations(pool_state.tokens, 2):
                # Try to sell 0.1% of the protocol balance
                sell_amount = Decimal("0.001") * pool_state.balances[sell_token.address]
                try:
                    amount_out, gas_used, _ = pool_state.get_amount_out(
                        sell_token, sell_amount, buy_token
                    )
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
                            sell_token=str(sell_token),
                            buy_token=str(buy_token),
                            error=str(e),
                        )
                    )
                    continue
        return failed_simulations

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
