import os
import subprocess
from typing import Optional


class AdapterContractHandler:
    @staticmethod
    def build_target(
        src_path: str,
        adapter_contract: str,
        signature: Optional[str],
        args: Optional[str],
    ):
        """
        Runs the buildRuntime Bash script in a subprocess with the provided arguments.

        :param src_path: Path to the script to be executed.
        :param adapter_contract: The contract name to be passed to the script.
        :param signature: The constructor signature to be passed to the script.
        :param args: The constructor arguments to be passed to the script.
        """

        script_path = "scripts/buildRuntime.sh"
        cmd = [script_path, "-c", adapter_contract]
        if signature:
            cmd.extend(["-s", signature, "-a", args])
        try:
            # Running the bash script with the provided arguments
            result = subprocess.run(
                [script_path, "-c", adapter_contract, "-s", signature, "-a", args],
                cwd=src_path,
                capture_output=True,
                text=True,
                check=True,
            )

            # Print standard output and error for debugging
            print("Output:\n", result.stdout)
            if result.stderr:
                print("Errors:\n", result.stderr)

        except subprocess.CalledProcessError as e:
            print(f"An error occurred: {e}")
            print("Error Output:\n", e.stderr)
