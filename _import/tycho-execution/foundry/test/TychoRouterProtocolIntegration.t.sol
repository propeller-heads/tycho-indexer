// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "./TychoRouterTestSetup.sol";
import "./protocols/UniswapV4Utils.sol";
import "@src/executors/BebopExecutor.sol";

contract TychoRouterTestProtocolIntegration is TychoRouterTestSetup {
    function testMultiProtocolIntegration() public {
        // Test created with calldata from our router encoder.
        //
        //  DAI ─(USV2)─> WETH ─(bal)─> WBTC ─(curve)─> USDT ─(ekubo)─> ETH ─(USV4)─> USDC

        deal(DAI_ADDR, ALICE, 1500 ether);
        uint256 balanceBefore = address(ALICE).balance;

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(DAI_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);
        bytes memory callData = loadCallDataFromFile("test_multi_protocol");
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = address(ALICE).balance;

        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, 732214216964381330);
    }
}
