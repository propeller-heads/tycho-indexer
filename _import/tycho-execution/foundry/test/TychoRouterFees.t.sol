// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "./TychoRouterTestSetup.sol";
import {FeeCalculator} from "@src/FeeCalculator.sol";
import {
    Vault__UnexpectedNonZeroCount,
    Vault__UnexpectedInputDelta
} from "@src/Vault.sol";
import {TychoRouter__AmountOutNotFullyReceived} from "@src/TychoRouter.sol";

contract TychoRouterFeesTest is TychoRouterTestSetup {
    FeeCalculator feeCalculator;
    address routerFeeReceiver;
    address solverFeeReceiver;

    bytes32 public constant ROUTER_FEE_SETTER_ROLE =
        0x9939157be7760e9462f1d5a0dcad88b616ddc64138e317108b40b1cf55601348;

    function setUp() public override {
        super.setUp();

        // Deploy and configure FeeCalculator
        feeCalculator = new FeeCalculator();
        feeCalculator.grantRole(ROUTER_FEE_SETTER_ROLE, FEE_SETTER);

        routerFeeReceiver = makeAddr("routerFeeReceiver");
        solverFeeReceiver = makeAddr("solverFeeReceiver");

        // Set fee calculator in router
        vm.prank(FEE_SETTER);
        tychoRouter.setFeeCalculator(address(feeCalculator));
    }

    function testSingleSwapWithAllFeeTypes() public {
        // Set up fees: 1% router fee on output, 2% solver fee, 10% router fee on solver fee
        vm.startPrank(FEE_SETTER);
        feeCalculator.setRouterFeeReceiver(routerFeeReceiver);
        feeCalculator.setRouterFeeOnOutput(100); // 1%
        feeCalculator.setRouterFeeOnSolverFee(1000); // 10%
        vm.stopPrank();

        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        // When fees are present, encode receiver as TychoRouter (not ALICE)
        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, false);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 1900 * 1e18;

        uint256 swapOutput = tychoRouter.singleSwap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            ALICE,
            200, // 2% solverFeeBps
            solverFeeReceiver,
            0,
            swap
        );
        vm.stopPrank();

        // Flow with fees:
        // 1. Swap sends full output to router (2018817438608734439722 DAI)
        // 2. takeFees deducts fees and credits fee recipients' vaults
        // 3. Router transfers amountOut (after fees) to ALICE's address
        // 4. ALICE receives 1958252915450472406531 DAI in her address
        // 5. Fee recipients have fees in their vaults

        // Expected fees with all three fee types:
        // 1. solverFee = 2018817438608734439722 * 200 / 10000 = 40376348772174688794
        //    routerFeeOnSolverFee = 40376348772174688794 * 1000 / 10000 = 4037634877217468879
        //    solverPortion = 40376348772174688794 - 4037634877217468879 = 36338713894957219915
        // 2. routerFeeOnOutput = 2018817438608734439722 * 100 / 10000 = 20188174386087344397 (calculated on original amount)
        //    totalRouterFee = 4037634877217468879 + 20188174386087344397 = 24225809263304813276
        // 3. amountOut = 2018817438608734439722 - 36338713894957219915 - 24225809263304813276 = 1958252915450472406531
        uint256 expectedRouterFee = 24225809263304813276;
        uint256 expectedSolverFee = 36338713894957219915;
        uint256 expectedAmountOut = 1958252915450472406531;

        assertEq(swapOutput, expectedAmountOut);

        // Check router fee receiver vault balance
        uint256 routerFeeReceiverBalance = tychoRouter.balanceOf(
            routerFeeReceiver, uint256(uint160(DAI_ADDR))
        );
        assertEq(routerFeeReceiverBalance, expectedRouterFee);

        // Check solver fee receiver vault balance
        uint256 solverFeeReceiverBalance = tychoRouter.balanceOf(
            solverFeeReceiver, uint256(uint160(DAI_ADDR))
        );
        assertEq(solverFeeReceiverBalance, expectedSolverFee);

        // Check ALICE received correct amount in her address (not vault)
        uint256 userBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertEq(userBalance, expectedAmountOut);
    }

    function testSingleSwapCircumventFeesFails() public {
        // Set up fees: 1% router fee on output
        vm.startPrank(FEE_SETTER);
        feeCalculator.setRouterFeeReceiver(routerFeeReceiver);
        feeCalculator.setRouterFeeOnOutput(100); // 1%
        vm.stopPrank();

        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);

        // Give router some DAI balance to simulate the router already holding tokens
        // The transfer shouldn't fail with insufficient balance (we would like it
        // to fail in _finalizeBalances instead)
        deal(DAI_ADDR, address(tychoRouter), 3000 * 1e18);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        // User tries to circumvent fees by encoding receiver as themselves instead of router
        bytes memory protocolData = encodeUniswapV2Swap(
            DAI_WETH_UNIV2_POOL,
            ALICE, // WILL REVERT: Should be TychoRouter when fees > 0
            false
        );

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 1900 * 1e18;

        // Execute swap - this should fail because:
        // 1. Swap sends tokens to ALICE (not router)
        // 2. takeFees calculates fees (amountOut < amountOutBeforeFees)
        // 3. Router checks if it received the full amount
        // 4. Router didn't receive the tokens → reverts with
        //    Vault__UnexpectedNonZeroCount(1). This happens because when using
        //    InputSource.TransferFrom, no negative deltas are allowed at all.
        vm.expectRevert(
            abi.encodeWithSelector(Vault__UnexpectedNonZeroCount.selector, 1)
        );
        tychoRouter.singleSwap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            ALICE,
            0, // solverFeeBps
            address(0), // solverFeeReceiver
            0,
            swap
        );
        vm.stopPrank();
    }

    function testSingleSwapWithSolverFees() public {
        // Tests swapping WETH -> DAI on a USV2 pool with fees and solver contribution
        // Swap is 1 WETH for 2018.8 DAI (2018817438608734439722)
        // Solver takes 1% ->  20.18 DAI (20188174386087344397)

        deal(WETH_ADDR, ALICE, 1 ether);
        uint256 balanceBefore = IERC20(DAI_ADDR).balanceOf(ALICE);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, type(uint256).max);

        bytes memory callData =
            loadCallDataFromFile("test_single_swap_with_solver_fees");
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertTrue(success, "Call Failed");
        uint256 expectedAmountOut = 1998629264222647095325;
        assertEq(balanceAfter - balanceBefore, expectedAmountOut);

        uint256 expectedFeeAmount = 20188174386087344397;

        // Check solver fee receiver vault balance (BOB)
        uint256 solverFeeReceiverBalance =
            tychoRouter.balanceOf(BOB, uint256(uint160(DAI_ADDR)));
        assertEq(solverFeeReceiverBalance, expectedFeeAmount);
    }

    function testSingleSwapWithFeesAndContribution() public {
        // Tests swapping WETH -> DAI on a USV2 pool with fees and solver contribution
        // Swap is 1 WETH for      2018.8 DAI (2018817438608734439722)
        // Tycho Router takes 1% -> 20.18 DAI (20188174386087344397)
        // Solver takes 1% ->       20.18 DAI (20188174386087344397)
        // But (for some reason) the client contributes with at most 22 DAI

        vm.startPrank(FEE_SETTER);
        feeCalculator.setRouterFeeReceiver(routerFeeReceiver);
        feeCalculator.setRouterFeeOnOutput(100); // 1%
        vm.stopPrank();

        deal(WETH_ADDR, ALICE, 1 ether);
        uint256 balanceBefore = IERC20(DAI_ADDR).balanceOf(ALICE);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, type(uint256).max);

        // deal contribution to client
        uint256 contribution = 22_000000000000000000;
        deal(DAI_ADDR, ALICE, contribution);
        IERC20(DAI_ADDR).approve(tychoRouterAddr, contribution);
        tychoRouter.deposit(DAI_ADDR, contribution);
        bytes memory callData = loadCallDataFromFile(
            "test_single_swap_with_fees_and_solver_contribution"
        );
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertTrue(success, "Call Failed");
        uint256 expectedAmountOut = 2000_000000000000000000;
        assertEq(balanceAfter - balanceBefore, expectedAmountOut);

        uint256 expectedFeeAmount = 20188174386087344397;
        // Check router fee receiver vault balance
        uint256 routerFeeReceiverBalance = tychoRouter.balanceOf(
            routerFeeReceiver, uint256(uint160(DAI_ADDR))
        );
        assertEq(routerFeeReceiverBalance, expectedFeeAmount);

        // Check solver fee receiver vault balance (BOB)
        uint256 solverFeeReceiverBalance =
            tychoRouter.balanceOf(BOB, uint256(uint160(DAI_ADDR)));
        assertEq(solverFeeReceiverBalance, expectedFeeAmount);
    }
}
