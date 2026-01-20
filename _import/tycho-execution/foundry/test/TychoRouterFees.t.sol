// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "./TychoRouterTestSetup.sol";
import {FeeCalculator} from "@src/FeeCalculator.sol";
import {
    Vault__UnexpectedNegativeCount,
    Vault__UnexpectedInputDelta
} from "@src/Vault.sol";

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
        bytes memory protocolData = encodeUniswapV2Swap(
            DAI_WETH_UNIV2_POOL,
            address(tychoRouter), // Swap sends to router since fees > 0
            false,
            RestrictTransferFrom.TransferType.TransferFrom
        );

        // TODO remove when vault crediting PR is merged. This is to simulate
        // the delta accounting being credited after the final swap (which will only
        // be done if the final swap receiver is rightfully set to be the TychoRouter)
        tychoRouter.exposedDeltaAccounting(DAI_ADDR, 2018817438608734439722);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 1900 * 1e18;

        uint256 swapOutput = tychoRouter.singleSwap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            ALICE,
            true,
            200, // 2% solverFeeBps
            solverFeeReceiver,
            swap
        );
        vm.stopPrank();

        // Flow with fees:
        // 1. Swap sends full output to router (2018817438608734439722 DAI)
        // 2. takeFees deducts fees and credits fee recipients' vaults
        // 3. Router transfers amountOut (after fees) to ALICE's address
        // 4. ALICE receives 1958656678938194153419 DAI in her address
        // 5. Fee recipients have fees in their vaults

        // Expected fees with all three fee types:
        // 1. solverFee = 2018817438608734439722 * 200 / 10000 = 40376348772174688794
        //    routerFeeOnSolverFee = 40376348772174688794 * 1000 / 10000 = 4037634877217468879
        //    solverPortion = 40376348772174688794 - 4037634877217468879 = 36338713894957219915
        //    amountAfterSolverFee = 2018817438608734439722 - 40376348772174688794 = 1978441089836559750928
        // 2. routerFeeOnOutput = 1978441089836559750928 * 100 / 10000 = 19784410898365597509
        //    amountOut = 1978441089836559750928 - 19784410898365597509 = 1958656678938194153419
        //    totalRouterFee = 4037634877217468879 + 19784410898365597509 = 23822045775583066388
        uint256 expectedRouterFee = 23822045775583066388;
        uint256 expectedSolverFee = 36338713894957219915;
        uint256 expectedAmountOut = 1958656678938194153419;

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
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        // User tries to circumvent fees by encoding receiver as themselves instead of router
        bytes memory protocolData = encodeUniswapV2Swap(
            DAI_WETH_UNIV2_POOL,
            ALICE, // WILL REVERT: Should be TychoRouter when fees > 0
            false,
            RestrictTransferFrom.TransferType.TransferFrom
        );

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 1900 * 1e18;

        // Execute swap - this should fail because:
        // 1. Swap sends tokens to ALICE (not router)
        // 2. takeFees calculates fees (amountOut < amountOutBeforeFees)
        // 3. Router tries to transfer amountOut to ALICE
        // 4. Router doesn't have the tokens → reverts with insufficient balance
        vm.expectRevert();
        tychoRouter.singleSwap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            ALICE,
            true,
            0, // solverFeeBps
            address(0), // solverFeeReceiver
            swap
        );
        vm.stopPrank();
    }
}
