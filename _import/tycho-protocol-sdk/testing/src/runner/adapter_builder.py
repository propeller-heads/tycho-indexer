import os
import subprocess
from typing import Optional


class AdapterContractBuilder:
    def __init__(self, src_path: str):
        self.src_path = src_path

    def find_contract(self, adapter_contract: str):
        """
        Finds the contract file in the provided source path.

        :param adapter_contract: The contract name to be found.
        :return: The path to the contract file.
        """
        contract_path = os.path.join(
            self.src_path,
            "out",
            f"{adapter_contract}.sol",
            f"{adapter_contract}.evm.runtime",
        )
        if not os.path.exists(contract_path):
            raise FileNotFoundError(f"Contract {adapter_contract} not found.")

        return contract_path

    def build_target(
        self, adapter_contract: str, signature: Optional[str], args: Optional[str]
    ) -> str:
        """
        Runs the buildRuntime Bash script in a subprocess with the provided arguments.

        :param src_path: Path to the script to be executed.
        :param adapter_contract: The contract name to be passed to the script.
        :param signature: The constructor signature to be passed to the script.
        :param args: The constructor arguments to be passed to the script.

        :return: The path to the contract file.
        """

        script_path = "scripts/buildRuntime.sh"
        cmd = [script_path, "-c", adapter_contract]
        if signature:
            cmd.extend(["-s", signature, "-a", args])
        try:
            # Running the bash script with the provided arguments
            result = subprocess.run(
                [script_path, "-c", adapter_contract, "-s", signature, "-a", args],
                cwd=self.src_path,
                capture_output=True,
                text=True,
                check=True,
            )

            # Print standard output and error for debugging
            print("Output:\n", result.stdout)
            if result.stderr:
                print("Errors:\n", result.stderr)

            return self.find_contract(adapter_contract)

        except subprocess.CalledProcessError as e:
            print(f"An error occurred: {e}")
            print("Error Output:\n", e.stderr)
