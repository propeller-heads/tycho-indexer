// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

contract TestUtils is Test {
    constructor() {}

    function loadCallDataFromFile(string memory testName)
        internal
        view
        returns (bytes memory)
    {
        string memory fileContent = vm.readFile("./test/assets/calldata.txt");
        string[] memory lines = vm.split(fileContent, "\n");

        for (uint256 i = 0; i < lines.length; i++) {
            string[] memory parts = vm.split(lines[i], ":");
            if (
                parts.length >= 2
                    && keccak256(bytes(parts[0])) == keccak256(bytes(testName))
            ) {
                return vm.parseBytes(parts[1]);
            }
        }

        revert("Test calldata not found");
    }

    /// @notice Export the runtime bytecode of a deployed contract to a JSON file.
    /// @dev
    /// This function captures the runtime bytecode (including immutables) of the deployed
    /// contract at `contractAddr` and writes it to a JSON file under `test/<name>.runtime.json`.
    /// The resulting file is intended to be used for SDK testing in another repository and
    /// should be copied there. It **should not** be committed in this repository.
    /// @param contractAddr The address of the deployed contract to extract runtime bytecode from.
    /// @param contractName The base filename for the exported JSON file.
    function exportRuntimeBytecode(
        address contractAddr,
        string memory contractName
    ) internal {
        bytes memory runtime = contractAddr.code;
        string memory hexCode = vm.toString(runtime);
        string memory json =
            string.concat('{"runtimeBytecode":"', hexCode, '"}');

        string memory path =
            string.concat("test/", contractName, ".runtime.json");
        vm.writeFile(path, json);
    }
}
