// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import "forge-std/Script.sol";

contract buildRuntime is Script {
    function run() external {
        bytes memory args = vm.envBytes("__PROPELLER_DEPLOY_ARGS");
        string memory contractRef = vm.envString("__PROPELLER_CONTRACT");
        string memory outFilePath = vm.envString("__PROPELLER_OUT_FILE");
        address deployedContract = deployCode(contractRef, args);

        bytes memory deployedCode = deployedContract.code;
        vm.writeFileBinary(outFilePath, deployedCode);
    }
}
