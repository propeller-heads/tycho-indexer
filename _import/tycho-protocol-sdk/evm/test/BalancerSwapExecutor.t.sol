// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./SwapExecutor.t.sol";
import "../src/balancer-v2/BalancerSwapExecutor.sol";

contract TestBalancerSwapExecutor is SwapExecutorTest {
    BalancerSwapExecutor balancer;
    IERC20 USDC = IERC20(USDC_ADDR);
    IERC20 USDT = IERC20(USDT_ADDR);

    constructor() {}

    function setUp() public {
        //Fork
        uint256 forkBlock = 16000000;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);

        //Setup
        balancer = new BalancerSwapExecutor();
    }

    function testBalancerSwap() public {
        //Set up
        uint256 sellAmount = 1000_000000;
        uint256 expectedAmount = 998_919380; //Swap 1k USDT for 998 USDC
        bool exactOut = false;
        // This is required because balancer does a transferFrom sender.
        // That also means we need to do this approval with our swapRouter.
        bool tokenApprovalNeeded = true;
        bytes memory protocolData = abi.encodePacked(
            USDT_ADDR,
            USDC_ADDR,
            DAI_USDC_USDT_balancer,
            bob,
            exactOut,
            tokenApprovalNeeded
        );

        // Logic
        vm.prank(address(balancer));
        deal(USDT_ADDR, address(balancer), sellAmount);
        vm.prank(executor);
        uint256 responseAmount = balancer.swap(sellAmount, protocolData);

        //Assertions
        assertEq(responseAmount, expectedAmount);
        assertEq(USDC.balanceOf(bob), expectedAmount);
        assertEq(USDT.balanceOf(address(balancer)), 0);
    }

    function testBalancerExactOutSwap() public {
        //Set up
        uint256 buyAmount = 1000_979168;
        uint256 expectedSellAmount = 1000 * 10 ** 6;
        bool exactOut = true;
        bool tokenApprovalNeeded = true;
        bytes memory protocolData = abi.encodePacked(
            USDC_ADDR,
            USDT_ADDR,
            DAI_USDC_USDT_balancer,
            bob,
            exactOut,
            tokenApprovalNeeded
        );

        //Logic
        // This is required because balancer does a transferFrom sender.
        // That also means we need to do this approval with our swapRouter.
        vm.prank(address(balancer));

        deal(USDC_ADDR, address(balancer), expectedSellAmount);
        vm.prank(executor);
        uint256 responseAmount = balancer.swap(buyAmount, protocolData);

        // //Assertions
        assertEq(responseAmount, expectedSellAmount);
        assertEq(USDT.balanceOf(bob), buyAmount);
        assertEq(USDC.balanceOf(address(balancer)), 0);
    }
}
