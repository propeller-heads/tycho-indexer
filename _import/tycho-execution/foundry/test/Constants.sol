// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "forge-std/Test.sol";

contract Constants is Test {
    address ADMIN = makeAddr("admin"); //admin=us
    address BOB = makeAddr("bob"); //bob=someone!=us
    address FUND_RESCUER = makeAddr("fundRescuer");
    address FEE_SETTER = makeAddr("feeSetter");
    address FEE_RECEIVER = makeAddr("feeReceiver");
    address EXECUTOR_SETTER = makeAddr("executorSetter");
    address ALICE = 0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2;
    uint256 ALICE_PK =
        0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234;

    // Dummy contracts
    address DUMMY = makeAddr("dummy");
    address DUMMY2 = makeAddr("dummy2");
    address PAUSER = makeAddr("pauser");
    address UNPAUSER = makeAddr("unpauser");

    // Assets
    address WETH_ADDR = address(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    address DAI_ADDR = address(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    address BAL_ADDR = address(0xba100000625a3754423978a60c9317c58a424e3D);
    address USDC_ADDR = address(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    address WBTC_ADDR = address(0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599);

    // uniswap v2
    address WETH_DAI_POOL = 0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11;
    address DAI_USDC_POOL = 0xAE461cA67B15dc8dc81CE7615e0320dA1A9aB8D5;
    address WETH_WBTC_POOL = 0xBb2b8038a1640196FbE3e38816F3e67Cba72D940;
    address USDC_WBTC_POOL = 0x004375Dff511095CC5A197A54140a24eFEF3A416;

    /**
     * @dev Deploys a dummy contract with non-empty bytecode
     */
    function deployDummyContract() internal {
        bytes memory minimalBytecode = hex"01"; // Single-byte bytecode
        // Deploy minimal bytecode
        vm.etch(DUMMY, minimalBytecode);
        vm.etch(DUMMY2, minimalBytecode);
    }
}
