// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import "forge-std/Script.sol";

contract buildRuntime is Script {
    function run() external {
        bytes memory deployArgs = getDeployArgs();
        string memory contractName = vm.envString("__PROPELLER_CONTRACT");
        string memory outFilePath = vm.envString("__PROPELLER_OUT_FILE");

        address deployedContract = deployContract(contractName, deployArgs);

        bytes memory deployedCode = deployedContract.code;
        vm.writeFileBinary(outFilePath, deployedCode);
    }

    function getDeployArgs() internal view returns (bytes memory) {
        try vm.envBytes("__PROPELLER_DEPLOY_ARGS") returns (bytes memory args) {
            return args;
        } catch {
            return "";
        }
    }

    function deployContract(string memory contractName, bytes memory args)
        internal
        returns (address)
    {
        if (args.length == 0) {
            return deployCode(contractName);
        } else {
            return deployCode(contractName, args);
        }
    }
}
