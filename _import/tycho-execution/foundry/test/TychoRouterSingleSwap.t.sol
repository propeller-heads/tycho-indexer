// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/UniswapV4Executor.sol";
import {TychoRouter} from "@src/TychoRouter.sol";
import "./TychoRouterTestSetup.sol";
import "./executors/UniswapV4Utils.sol";
import {SafeCallback} from "@uniswap/v4-periphery/src/base/SafeCallback.sol";

contract TychoRouterSingleSwapTest is TychoRouterTestSetup {
    function testSingleSwapPermit2() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2 using Permit2
        // 1 WETH   ->   DAI
        //       (USV2)
        vm.startPrank(ALICE);

        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);
        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(WETH_ADDR, tychoRouterAddr, amountIn);

        bytes memory protocolData = encodeUniswapV2Swap(
            WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false
        );

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        tychoRouter.singleSwapPermit2(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            2659881924818443699786,
            false,
            false,
            ALICE,
            permitSingle,
            signature,
            swap
        );

        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertEq(daiBalance, 2659881924818443699787);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), 0);

        vm.stopPrank();
    }

    function testSingleSwapNoPermit2() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // Checks amount out at the end
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        // Approve the tokenIn to be transferred to the router
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        bytes memory protocolData = encodeUniswapV2Swap(
            WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false
        );

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 2600 * 1e18;
        uint256 amountOut = tychoRouter.singleSwap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            false,
            false,
            ALICE,
            swap
        );

        uint256 expectedAmount = 2659881924818443699787;
        assertEq(amountOut, expectedAmount);
        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertEq(daiBalance, expectedAmount);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), 0);

        vm.stopPrank();
    }

    function testSingleSwapUndefinedMinAmount() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // Checks amount out at the end
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        bytes memory protocolData = encodeUniswapV2Swap(
            WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false
        );

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        vm.expectRevert(TychoRouter__UndefinedMinAmountOut.selector);
        tychoRouter.singleSwap(
            amountIn, WETH_ADDR, DAI_ADDR, 0, false, false, ALICE, swap
        );
    }

    function testSingleSwapInsufficientApproval() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // Checks amount out at the end
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn - 1);

        bytes memory protocolData = encodeUniswapV2Swap(
            WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false
        );

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 2600 * 1e18;
        vm.expectRevert();
        tychoRouter.singleSwap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            false,
            false,
            ALICE,
            swap
        );
    }

    function testSingleSwapNegativeSlippageFailure() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // Checks amount out at the end
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        // Approve the tokenIn to be transferred to the router
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        bytes memory protocolData = encodeUniswapV2Swap(
            WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false
        );

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 5600 * 1e18;

        vm.expectRevert(
            abi.encodeWithSelector(
                TychoRouter__NegativeSlippage.selector,
                2659881924818443699787, // actual amountOut
                minAmountOut
            )
        );
        tychoRouter.singleSwap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            false,
            false,
            ALICE,
            swap
        );
    }

    function testSingleSwapWrapETH() public {
        uint256 amountIn = 1 ether;
        deal(ALICE, amountIn);
        vm.startPrank(ALICE);

        IAllowanceTransfer.PermitSingle memory emptyPermitSingle =
        IAllowanceTransfer.PermitSingle({
            details: IAllowanceTransfer.PermitDetails({
                token: address(0),
                amount: 0,
                expiration: 0,
                nonce: 0
            }),
            spender: address(0),
            sigDeadline: 0
        });

        bytes memory protocolData = encodeUniswapV2Swap(
            WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false
        );

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 amountOut = tychoRouter.singleSwapPermit2{value: amountIn}(
            amountIn,
            address(0),
            DAI_ADDR,
            1000_000000,
            true,
            false,
            ALICE,
            emptyPermitSingle,
            "",
            swap
        );
        uint256 expectedAmount = 2659881924818443699787;
        assertEq(amountOut, expectedAmount);
        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertEq(daiBalance, expectedAmount);
        assertEq(ALICE.balance, 0);

        vm.stopPrank();
    }

    function testSingleSwapUnwrapETH() public {
        // DAI -> WETH with unwrapping to ETH
        uint256 amountIn = 3000 ether;
        deal(DAI_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(DAI_ADDR, tychoRouterAddr, amountIn);

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_ADDR, WETH_DAI_POOL, tychoRouterAddr, true);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 amountOut = tychoRouter.singleSwapPermit2(
            amountIn,
            DAI_ADDR,
            address(0),
            1000_000000,
            false,
            true,
            ALICE,
            permitSingle,
            signature,
            swap
        );

        uint256 expectedAmount = 1120007305574805922;
        assertEq(amountOut, expectedAmount);
        assertEq(ALICE.balance, expectedAmount);

        vm.stopPrank();
    }

    function testSingleSwapIntegration() public {
        // Tests swapping WETH -> DAI on a USV2 pool with regular approvals
        deal(WETH_ADDR, ALICE, 1 ether);
        uint256 balancerBefore = IERC20(DAI_ADDR).balanceOf(ALICE);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, type(uint256).max);
        // Encoded solution generated using `test_single_swap_strategy_encoder_no_permit2`
        (bool success,) = tychoRouterAddr.call(
            hex"20144a070000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000006b175474e89094c44da98b954eedeac495271d0f00000000000000000000000000000000000000000000008f1d5c1cae3740000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000515615deb798bb3e4dfa0139dfa1b3d433cc23b72fc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a478c2975ab1ea89e8196811f51a7b7ade33eb113ede3eca2a72b3aecc820e955b36f38437d0139500000000000000000000000000000000"
        );

        vm.stopPrank();

        uint256 balancerAfter = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertTrue(success, "Call Failed");
        assertEq(balancerAfter - balancerBefore, 2659881924818443699787);
    }

    function testSingleSwapIntegrationPermit2() public {
        // Tests swapping WETH -> DAI on a USV2 pool with permit2
        deal(WETH_ADDR, ALICE, 1 ether);
        uint256 balancerBefore = IERC20(DAI_ADDR).balanceOf(ALICE);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);
        // Encoded solution generated using `test_single_swap_strategy_encoder`
        (bool success,) = tychoRouterAddr.call(
            hex"30ace1b10000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000006b175474e89094c44da98b954eedeac495271d0f0000000000000000000000000000000000000000000000903146e5f6c59c064b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000006817833200000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ede3eca2a72b3aecc820e955b36f38437d013950000000000000000000000000000000000000000000000000000000067effd3a00000000000000000000000000000000000000000000000000000000000001e0000000000000000000000000000000000000000000000000000000000000026000000000000000000000000000000000000000000000000000000000000000417efea09004d5d40d8d072e1ce0a425507717ea485c765eb90c170859197d362b502fb039b4f5cdce57318ecfe3ab276d1ac87771eb5d017b253a8f4107e6a20b1b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000515615deb798bb3e4dfa0139dfa1b3d433cc23b72fc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a478c2975ab1ea89e8196811f51a7b7ade33eb113ede3eca2a72b3aecc820e955b36f38437d0139500000000000000000000000000000000"
        );

        vm.stopPrank();

        uint256 balancerAfter = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertTrue(success, "Call Failed");
        assertEq(balancerAfter - balancerBefore, 2659881924818443699787);
    }
}
