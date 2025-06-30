import itertools
import os
import shutil
import subprocess
import traceback
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Optional, Callable, Any

import yaml
from tycho_simulation_py.evm.decoders import ThirdPartyPoolTychoDecoder
from tycho_simulation_py.evm.storage import TychoDBSingleton
from tycho_simulation_py.models import EVMBlock
from pydantic import BaseModel
from tycho_indexer_client.dto import (
    Chain,
    ProtocolComponentsParams,
    ProtocolStateParams,
    ContractStateParams,
    ProtocolComponent,
    ResponseProtocolState,
    HexBytes,
    ResponseAccount,
    Snapshot,
    TracedEntryPointParams,
)
from tycho_indexer_client.rpc_client import TychoRPCClient

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
    def __init__(
        self, success: bool, step: Optional[str] = None, message: Optional[str] = None
    ):
        self.success = success
        self.step = step
        self.message = message

    @classmethod
    def Passed(cls):
        return cls(success=True)

    @classmethod
    def Failed(cls, step: str, message: str):
        return cls(success=False, step=step, message=message)


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
        print(f"Running {len(self.config.tests)} tests ...\n")
        print("--------------------------------\n")

        failed_tests: list[str] = []
        count = 1

        for test in self.config.tests:
            print(f"TEST {count}: {test.name}")

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

            result: TestResult = self.tycho_runner.run_with_rpc_server(
                self.validate_state,
                test.expected_components,
                test.stop_block,
                test.initialized_accounts or [],
            )

            if result.success:
                print(f"\n✅ {test.name} passed.\n")
            else:
                failed_tests.append(test.name)
                print(f"\n❗️ {test.name} failed on {result.step}: {result.message}\n")

            print("--------------------------------\n")
            count += 1

        print(
            "\nTests finished! \n"
            f"RESULTS: {len(self.config.tests) - len(failed_tests)}/{len(self.config.tests)} passed.\n"
        )
        if failed_tests:
            print("Failed tests:")
            for failed_test in failed_tests:
                print(f"- {failed_test}")
        print("\n")

    def validate_state(
        self,
        expected_components: list[ProtocolComponentWithTestConfig],
        stop_block: int,
        initialized_accounts: list[str],
    ) -> TestResult:
        """Validate the current protocol state against the expected state."""
        protocol_components = self.tycho_rpc_client.get_protocol_components(
            ProtocolComponentsParams(protocol_system="test_protocol")
        ).protocol_components
        protocol_states = self.tycho_rpc_client.get_protocol_state(
            ProtocolStateParams(protocol_system="test_protocol")
        ).states
        components_by_id: dict[str, ProtocolComponent] = {
            component.id: component for component in protocol_components
        }

        try:
            # Step 1: Validate the protocol components
            step = "Protocol component validation"

            for expected_component in expected_components:
                comp_id = expected_component.id.lower()
                if comp_id not in components_by_id:
                    return TestResult.Failed(
                        step=step,
                        message=f"'{comp_id}' not found in protocol components. "
                        f"Available components: {set(components_by_id.keys())}",
                    )

                diff = ProtocolComponentExpectation(
                    **components_by_id[comp_id].dict()
                ).compare(ProtocolComponentExpectation(**expected_component.dict()))
                if diff is not None:
                    return TestResult.Failed(step=step, message=diff)

            print(f"\n✅ {step} passed.\n")

            # Step 2: Validate the token balances
            step = "Token balance validation"

            if not self.config.skip_balance_check:
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

                        node_balance = get_token_balance(token, comp_id, stop_block)
                        if node_balance != tycho_balance:
                            return TestResult.Failed(
                                step=step,
                                message=f"Balance mismatch for {comp_id}:{token} at block {stop_block}: got {node_balance} "
                                f"from rpc call and {tycho_balance} from Substreams",
                            )
                print(f"\n✅ {step} passed.\n")

            else:
                print(f"\nℹ️  {step} skipped. \n")

            # Step 3: Validate the simulation
            step = "Simulation validation"

            # Loads from Tycho-Indexer the state of all the contracts that are related to the protocol components.
            simulation_components: list[str] = [
                c.id for c in expected_components if c.skip_simulation is False
            ]

            related_contracts: set[str] = set()
            for account in self.config.initialized_accounts or []:
                related_contracts.add(account)
            for account in initialized_accounts or []:
                related_contracts.add(account)

            # Collect all contracts that are related to the simulation components
            filtered_components: list[ProtocolComponent] = []
            component_related_contracts: set[str] = set()
            for component in protocol_components:
                # Filter out components that are not set to be used for the simulation
                if component.id in simulation_components:
                    # Collect component contracts
                    for a in component.contract_ids:
                        component_related_contracts.add(a.hex())
                    # Collect DCI detected contracts
                    traces_results = self.tycho_rpc_client.get_traced_entry_points(
                        TracedEntryPointParams(
                            protocol_system="test_protocol",
                            component_ids=[component.id],
                        )
                    ).traced_entry_points.values()
                    for traces in traces_results:
                        for _, trace in traces:
                            component_related_contracts.update(
                                trace["accessed_slots"].keys()
                            )
                    filtered_components.append(component)

            # Check if any of the initialized contracts are not listed as component contract dependencies
            unspecified_contracts: list[str] = [
                c for c in related_contracts if c not in component_related_contracts
            ]

            related_contracts.update(component_related_contracts)

            contract_states = self.tycho_rpc_client.get_contract_state(
                ContractStateParams(contract_ids=list(related_contracts))
            ).accounts
            if len(filtered_components):

                if len(unspecified_contracts):
                    print(
                        f"⚠️ The following initialized contracts are not listed as component contract dependencies: {unspecified_contracts}. "
                        f"Please ensure that, if they are required for this component's simulation, they are specified under the Protocol Component's contract field."
                    )

                simulation_failures = self.simulate_get_amount_out(
                    stop_block, protocol_states, filtered_components, contract_states
                )
                if len(simulation_failures):
                    error_msgs: list[str] = []
                    for pool_id, failures in simulation_failures.items():
                        failures_formatted: list[str] = [
                            f"{f.sell_token} -> {f.buy_token}: {f.error}"
                            for f in failures
                        ]
                        error_msgs.append(
                            f"Pool {pool_id} failed simulations: {', '.join(failures_formatted)}"
                        )
                    return TestResult.Failed(step=step, message="\n".join(error_msgs))
                print(f"\n✅ {step} passed.\n")
            else:
                print(f"\nℹ️  {step} skipped.\n")
            return TestResult.Passed()
        except Exception as e:
            error_message = f"An error occurred: {str(e)}\n" + traceback.format_exc()
            return TestResult.Failed(step=step, message=error_message)

    def simulate_get_amount_out(
        self,
        block_number: int,
        protocol_states: list[ResponseProtocolState],
        protocol_components: list[ProtocolComponent],
        contract_states: list[ResponseAccount],
    ) -> dict[str, list[SimulationFailure]]:
        TychoDBSingleton.initialize()

        block_header = get_block_header(block_number)
        block: EVMBlock = EVMBlock(
            id=block_number,
            ts=datetime.fromtimestamp(block_header.timestamp),
            hash_=block_header.hash.hex(),
        )

        failed_simulations: dict[str, list[SimulationFailure]] = {}

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

        TychoDBSingleton.clear_instance()

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

        for component in protocol_components:
            if component.id not in decoded:
                failed_simulations[component.id] = [
                    SimulationFailure(
                        pool_id=component.id,
                        sell_token=component.tokens[0].hex(),
                        buy_token=component.tokens[1].hex(),
                        error="Pool not found in decoded state.",
                    )
                ]

        for pool_state in decoded.values():
            pool_id = pool_state.id_
            if not pool_state.balances:
                raise ValueError(f"Missing balances for pool {pool_id}")
            for sell_token, buy_token in itertools.permutations(pool_state.tokens, 2):
                for prctg in ["0.001", "0.01", "0.1"]:
                    # Try to sell 0.1% of the protocol balance
                    try:
                        sell_amount = (
                            Decimal(prctg) * pool_state.balances[sell_token.address]
                        )
                        amount_out, gas_used, _ = pool_state.get_amount_out(
                            sell_token, sell_amount, buy_token
                        )
                        print(
                            f"Amount out for {pool_id}: {sell_amount} {sell_token} -> {amount_out} {buy_token} - "
                            f"Gas used: {gas_used}"
                        )
                    except Exception as e:
                        print(
                            f"Error simulating get_amount_out for {pool_id}: {sell_token} -> {buy_token} at block {block_number}. "
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
    def build_spkg(
        yaml_file_path: str, modify_func: Callable[[dict[str, Any]], None]
    ) -> str:
        """Build a Substreams package with modifications to the YAML file."""
        backup_file_path = f"{yaml_file_path}.backup"
        shutil.copy(yaml_file_path, backup_file_path)

        with open(yaml_file_path, "r") as file:
            data = yaml.safe_load(file)

        modify_func(data)
        spkg_name = f"{yaml_file_path.rsplit('/', 1)[0]}/{data['package']['name'].replace('_', '-')}-{data['package']['version']}.spkg"

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
    def update_initial_block(data: dict[str, Any], start_block: int) -> None:
        """Update the initial block for all modules in the configuration data."""
        for module in data["modules"]:
            module["initialBlock"] = start_block
