// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/UniswapV4Executor.sol";
import {TychoRouter} from "@src/TychoRouter.sol";
import "./TychoRouterTestSetup.sol";
import "./executors/UniswapV4Utils.sol";
import {SafeCallback} from "@uniswap/v4-periphery/src/base/SafeCallback.sol";

contract TychoRouterTest is TychoRouterTestSetup {
    bytes32 public constant EXECUTOR_SETTER_ROLE =
        0x6a1dd52dcad5bd732e45b6af4e7344fa284e2d7d4b23b5b09cb55d36b0685c87;
    bytes32 public constant FEE_SETTER_ROLE =
        0xe6ad9a47fbda1dc18de1eb5eeb7d935e5e81b4748f3cfc61e233e64f88182060;
    bytes32 public constant PAUSER_ROLE =
        0x65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a;
    bytes32 public constant FUND_RESCUER_ROLE =
        0x912e45d663a6f4cc1d0491d8f046e06c616f40352565ea1cdb86a0e1aaefa41b;

    event CallbackVerifierSet(address indexed callbackVerifier);
    event Withdrawal(
        address indexed token, uint256 amount, address indexed receiver
    );

    function testSetExecutorsValidRole() public {
        // Set single executor
        address[] memory executors = new address[](1);
        executors[0] = DUMMY;
        vm.startPrank(EXECUTOR_SETTER);
        tychoRouter.setExecutors(executors);
        vm.stopPrank();
        assert(tychoRouter.executors(DUMMY) == true);

        // Set multiple executors
        address[] memory executors2 = new address[](2);
        executors2[0] = DUMMY2;
        executors2[1] = DUMMY3;
        vm.startPrank(EXECUTOR_SETTER);
        tychoRouter.setExecutors(executors2);
        vm.stopPrank();
        assert(tychoRouter.executors(DUMMY2) == true);
        assert(tychoRouter.executors(DUMMY3) == true);
    }

    function testRemoveExecutorValidRole() public {
        vm.startPrank(EXECUTOR_SETTER);
        address[] memory executors = new address[](1);
        executors[0] = DUMMY;
        tychoRouter.setExecutors(executors);
        tychoRouter.removeExecutor(DUMMY);
        vm.stopPrank();
        assert(tychoRouter.executors(DUMMY) == false);
    }

    function testRemoveExecutorMissingSetterRole() public {
        vm.expectRevert();
        tychoRouter.removeExecutor(BOB);
    }

    function testSetExecutorsMissingSetterRole() public {
        vm.expectRevert();
        address[] memory executors = new address[](1);
        executors[0] = DUMMY;
        tychoRouter.setExecutors(executors);
    }

    function testWithdrawNative() public {
        vm.startPrank(FUND_RESCUER);
        // Send 100 ether to tychoRouter
        assertEq(tychoRouterAddr.balance, 0);
        assertEq(FUND_RESCUER.balance, 0);
        vm.deal(tychoRouterAddr, 100 ether);
        vm.expectEmit();
        emit Withdrawal(address(0), 100 ether, FUND_RESCUER);
        tychoRouter.withdrawNative(FUND_RESCUER);
        assertEq(tychoRouterAddr.balance, 0);
        assertEq(FUND_RESCUER.balance, 100 ether);
        vm.stopPrank();
    }

    function testWithdrawNativeFailures() public {
        vm.deal(tychoRouterAddr, 100 ether);
        vm.startPrank(FUND_RESCUER);
        vm.expectRevert(TychoRouter__AddressZero.selector);
        tychoRouter.withdrawNative(address(0));
        vm.stopPrank();

        // Not role FUND_RESCUER
        vm.startPrank(BOB);
        vm.expectRevert();
        tychoRouter.withdrawNative(FUND_RESCUER);
        vm.stopPrank();
    }

    function testWithdrawERC20Tokens() public {
        vm.startPrank(BOB);
        mintTokens(100 ether, tychoRouterAddr);
        vm.stopPrank();

        vm.startPrank(FUND_RESCUER);
        IERC20[] memory tokensArray = new IERC20[](3);
        tokensArray[0] = IERC20(address(tokens[0]));
        tokensArray[1] = IERC20(address(tokens[1]));
        tokensArray[2] = IERC20(address(tokens[2]));
        tychoRouter.withdraw(tokensArray, FUND_RESCUER);

        // Check balances after withdrawing
        for (uint256 i = 0; i < tokens.length; i++) {
            // slither-disable-next-line calls-loop
            assertEq(tokens[i].balanceOf(tychoRouterAddr), 0);
            // slither-disable-next-line calls-loop
            assertEq(tokens[i].balanceOf(FUND_RESCUER), 100 ether);
        }
        vm.stopPrank();
    }

    function testWithdrawERC20TokensFailures() public {
        mintTokens(100 ether, tychoRouterAddr);
        IERC20[] memory tokensArray = new IERC20[](3);
        tokensArray[0] = IERC20(address(tokens[0]));
        tokensArray[1] = IERC20(address(tokens[1]));
        tokensArray[2] = IERC20(address(tokens[2]));

        vm.startPrank(FUND_RESCUER);
        vm.expectRevert(TychoRouter__AddressZero.selector);
        tychoRouter.withdraw(tokensArray, address(0));
        vm.stopPrank();

        // Not role FUND_RESCUER
        vm.startPrank(BOB);
        vm.expectRevert();
        tychoRouter.withdraw(tokensArray, FUND_RESCUER);
        vm.stopPrank();
    }

    function testFeeSetting() public {
        vm.startPrank(FEE_SETTER);
        assertEq(tychoRouter.fee(), 0);
        tychoRouter.setFee(100);
        assertEq(tychoRouter.fee(), 100);
        vm.stopPrank();

        vm.startPrank(BOB);
        vm.expectRevert();
        tychoRouter.setFee(200);
        vm.stopPrank();
    }

    function testFeeReceiverSetting() public {
        vm.startPrank(FEE_SETTER);
        assertEq(tychoRouter.feeReceiver(), address(0));
        tychoRouter.setFeeReceiver(FEE_RECEIVER);
        assertEq(tychoRouter.feeReceiver(), FEE_RECEIVER);
        vm.stopPrank();

        vm.startPrank(BOB);
        vm.expectRevert();
        tychoRouter.setFeeReceiver(FEE_RECEIVER);
        vm.stopPrank();
    }

    function testPause() public {
        vm.startPrank(PAUSER);
        assertEq(tychoRouter.paused(), false);
        tychoRouter.pause();
        assertEq(tychoRouter.paused(), true);
        vm.stopPrank();

        vm.startPrank(UNPAUSER);
        tychoRouter.unpause();
        assertEq(tychoRouter.paused(), false);
        vm.stopPrank();

        vm.startPrank(UNPAUSER);
        vm.expectRevert();
        tychoRouter.unpause();
        vm.stopPrank();
    }

    function testPauseNonRole() public {
        vm.startPrank(BOB);
        vm.expectRevert();
        tychoRouter.pause();
        vm.stopPrank();
    }

    function testWrapETH() public {
        uint256 amount = 1 ether;
        vm.deal(BOB, amount);

        vm.startPrank(BOB);
        tychoRouter.wrapETH{value: amount}(amount);
        vm.stopPrank();

        assertEq(tychoRouterAddr.balance, 0);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), amount);
    }

    function testUnwrapETH() public {
        uint256 amount = 1 ether;
        deal(WETH_ADDR, tychoRouterAddr, amount);

        tychoRouter.unwrapETH(amount);

        assertEq(tychoRouterAddr.balance, amount);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testSplitSwapSimple() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // 1 WETH   ->   DAI
        //       (USV2)
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, tychoRouterAddr, amountIn);

        bytes memory protocolData = encodeUniswapV2Swap(
            WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false
        );

        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.exposedSplitSwap(amountIn, 2, pleEncode(swaps));

        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(tychoRouterAddr);
        assertEq(daiBalance, 2659881924818443699787);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testSplitSwapSimplePermit2() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2 using Permit2
        // 1 WETH   ->   DAI
        //       (USV2)
        vm.startPrank(ALICE);

        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);
        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(WETH_ADDR, amountIn);

        bytes memory protocolData = encodeUniswapV2Swap(
            WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false
        );

        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.splitSwapPermit2(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            2659881924818443699786,
            false,
            false,
            2,
            ALICE,
            permitSingle,
            signature,
            pleEncode(swaps)
        );

        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertEq(daiBalance, 2659881924818443699787);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), 0);

        vm.stopPrank();
    }

    function testSplitSwapMultipleHops() public {
        // Trade 1 WETH for USDC through DAI with 2 swaps on Uniswap V2
        // 1 WETH   ->   DAI   ->   USDC
        //       (univ2)     (univ2)
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, tychoRouterAddr, amountIn);

        bytes[] memory swaps = new bytes[](2);
        // WETH -> DAI
        swaps[0] = encodeSplitSwap(
            uint8(0),
            uint8(1),
            uint24(0),
            address(usv2Executor),
            encodeUniswapV2Swap(
                WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false
            )
        );

        // DAI -> USDC
        swaps[1] = encodeSplitSwap(
            uint8(1),
            uint8(2),
            uint24(0),
            address(usv2Executor),
            encodeUniswapV2Swap(DAI_ADDR, DAI_USDC_POOL, tychoRouterAddr, true)
        );

        tychoRouter.exposedSplitSwap(amountIn, 3, pleEncode(swaps));

        uint256 usdcBalance = IERC20(USDC_ADDR).balanceOf(tychoRouterAddr);
        assertEq(usdcBalance, 2644659787);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testSplitSwapSplitHops() public {
        // Trade 1 WETH for USDC through DAI and WBTC with 4 swaps on Uniswap V2
        //          ->   DAI   ->
        // 1 WETH                   USDC
        //          ->   WBTC  ->
        //       (univ2)     (univ2)
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, tychoRouterAddr, amountIn);

        bytes[] memory swaps = new bytes[](4);
        // WETH -> WBTC (60%)
        swaps[0] = encodeSplitSwap(
            uint8(0),
            uint8(1),
            (0xffffff * 60) / 100, // 60%
            address(usv2Executor),
            encodeUniswapV2Swap(
                WETH_ADDR, WETH_WBTC_POOL, tychoRouterAddr, false
            )
        );
        // WBTC -> USDC
        swaps[1] = encodeSplitSwap(
            uint8(1),
            uint8(2),
            uint24(0),
            address(usv2Executor),
            encodeUniswapV2Swap(
                WBTC_ADDR, USDC_WBTC_POOL, tychoRouterAddr, true
            )
        );
        // WETH -> DAI
        swaps[2] = encodeSplitSwap(
            uint8(0),
            uint8(3),
            uint24(0),
            address(usv2Executor),
            encodeUniswapV2Swap(
                WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false
            )
        );

        // DAI -> USDC
        swaps[3] = encodeSplitSwap(
            uint8(3),
            uint8(2),
            uint24(0),
            address(usv2Executor),
            encodeUniswapV2Swap(DAI_ADDR, DAI_USDC_POOL, tychoRouterAddr, true)
        );

        tychoRouter.exposedSplitSwap(amountIn, 4, pleEncode(swaps));

        uint256 usdcBalance = IERC20(USDC_ADDR).balanceOf(tychoRouterAddr);
        assertEq(usdcBalance, 2615491639);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testSplitSwapChecked() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // Does permit2 token approval and transfer
        // Checks amount out at the end
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);

        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(WETH_ADDR, amountIn);

        bytes memory protocolData = encodeUniswapV2Swap(
            WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false
        );

        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        uint256 minAmountOut = 2600 * 1e18;
        uint256 amountOut = tychoRouter.splitSwapPermit2(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            false,
            false,
            2,
            ALICE,
            permitSingle,
            signature,
            pleEncode(swaps)
        );

        uint256 expectedAmount = 2659881924818443699787;
        assertEq(amountOut, expectedAmount);
        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertEq(daiBalance, expectedAmount);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), 0);

        vm.stopPrank();
    }

    function testSplitSwapCheckedUndefinedMinAmount() public {
        // Min amount should always be non-zero. If zero, swap attempt should revert.

        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(WETH_ADDR, amountIn);

        bytes memory protocolData = encodeUniswapV2Swap(
            WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false
        );

        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;
        uint256 minAmountOut = 0;

        vm.expectRevert(TychoRouter__UndefinedMinAmountOut.selector);
        tychoRouter.splitSwapPermit2(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            false,
            false,
            2,
            ALICE,
            permitSingle,
            signature,
            pleEncode(swaps)
        );
        vm.stopPrank();
    }

    function testSplitSwapCheckedNoPermit2() public {
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

        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        uint256 minAmountOut = 2600 * 1e18;
        uint256 amountOut = tychoRouter.splitSwap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            false,
            false,
            2,
            ALICE,
            pleEncode(swaps)
        );

        uint256 expectedAmount = 2659881924818443699787;
        assertEq(amountOut, expectedAmount);
        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertEq(daiBalance, expectedAmount);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), 0);

        vm.stopPrank();
    }

    function testSplitSwapCheckedLessApprovalFailure() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // Fails while transferring the tokenIn to the router due to insufficient approval
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        // Approve less than the amountIn
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn - 1);

        bytes memory protocolData = encodeUniswapV2Swap(
            WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false
        );

        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        uint256 minAmountOut = 2600 * 1e18;
        vm.expectRevert();
        tychoRouter.splitSwap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            false,
            false,
            2,
            ALICE,
            pleEncode(swaps)
        );

        vm.stopPrank();
    }

    function testSplitSwapCheckedNegativeSlippageFailure() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // Does permit2 token approval and transfer
        // Checks amount out at the end and fails
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);

        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(WETH_ADDR, amountIn);

        bytes memory protocolData = encodeUniswapV2Swap(
            WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false
        );

        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        uint256 minAmountOut = 3000 * 1e18;
        vm.expectRevert(
            abi.encodeWithSelector(
                TychoRouter__NegativeSlippage.selector,
                2659881924818443699787, // actual amountOut
                minAmountOut
            )
        );
        tychoRouter.splitSwapPermit2(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            false,
            false,
            2,
            ALICE,
            permitSingle,
            signature,
            pleEncode(swaps)
        );
        vm.stopPrank();
    }

    function testSplitSwapFee() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // Does permit2 token approval and transfer
        // Takes fee at the end

        vm.startPrank(FEE_SETTER);
        tychoRouter.setFee(100);
        tychoRouter.setFeeReceiver(FEE_RECEIVER);
        vm.stopPrank();

        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);

        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(WETH_ADDR, amountIn);

        bytes memory protocolData = encodeUniswapV2Swap(
            WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false
        );

        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        uint256 amountOut = tychoRouter.splitSwapPermit2(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            2633283105570259262780,
            false,
            false,
            2,
            ALICE,
            permitSingle,
            signature,
            pleEncode(swaps)
        );

        uint256 expectedAmount = 2633283105570259262790;
        assertEq(amountOut, expectedAmount);
        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertEq(daiBalance, expectedAmount);
        assertEq(IERC20(DAI_ADDR).balanceOf(FEE_RECEIVER), 26598819248184436997);

        vm.stopPrank();
    }

    function testSplitSwapWrapETH() public {
        // Trade 1 ETH (and wrap it) for DAI with 1 swap on Uniswap V2

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

        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        uint256 amountOut = tychoRouter.splitSwapPermit2{value: amountIn}(
            amountIn,
            address(0),
            DAI_ADDR,
            2659881924818443699780,
            true,
            false,
            2,
            ALICE,
            emptyPermitSingle,
            "",
            pleEncode(swaps)
        );
        uint256 expectedAmount = 2659881924818443699787;
        assertEq(amountOut, expectedAmount);
        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertEq(daiBalance, expectedAmount);
        assertEq(ALICE.balance, 0);

        vm.stopPrank();
    }

    function testSplitSwapUnwrapETH() public {
        // Trade 3k DAI for WETH with 1 swap on Uniswap V2 and unwrap it at the end

        uint256 amountIn = 3_000 * 10 ** 18;
        deal(DAI_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);

        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(DAI_ADDR, amountIn);

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_ADDR, WETH_DAI_POOL, tychoRouterAddr, true);

        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        uint256 amountOut = tychoRouter.splitSwapPermit2(
            amountIn,
            DAI_ADDR,
            address(0),
            1120007305574805920,
            false,
            true,
            2,
            ALICE,
            permitSingle,
            signature,
            pleEncode(swaps)
        );

        uint256 expectedAmount = 1120007305574805922; // 1.12 ETH
        assertEq(amountOut, expectedAmount);
        assertEq(ALICE.balance, expectedAmount);

        vm.stopPrank();
    }

    function testSplitSwapSingleUSV3() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V3
        // 1 WETH   ->   DAI
        //       (USV3)
        uint256 amountIn = 10 ** 18;
        deal(WETH_ADDR, tychoRouterAddr, amountIn);

        uint256 expAmountOut = 1205_128428842122129186; //Swap 1 WETH for 1205.12 DAI
        bool zeroForOne = false;
        bytes memory protocolData = encodeUniswapV3Swap(
            WETH_ADDR, DAI_ADDR, tychoRouterAddr, DAI_WETH_USV3, zeroForOne
        );
        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv3Executor), protocolData
        );

        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.exposedSplitSwap(amountIn, 2, pleEncode(swaps));

        uint256 finalBalance = IERC20(DAI_ADDR).balanceOf(tychoRouterAddr);
        assertGe(finalBalance, expAmountOut);
    }

    function testSplitSwapSingleUSV3Permit2() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V3 using Permit2
        // 1 WETH   ->   DAI
        //       (USV3)
        vm.startPrank(ALICE);
        uint256 amountIn = 10 ** 18;
        deal(WETH_ADDR, ALICE, amountIn);
        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(WETH_ADDR, amountIn);

        uint256 expAmountOut = 1205_128428842122129186; //Swap 1 WETH for 1205.12 DAI
        bool zeroForOne = false;
        bytes memory protocolData = encodeUniswapV3Swap(
            WETH_ADDR, DAI_ADDR, tychoRouterAddr, DAI_WETH_USV3, zeroForOne
        );
        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv3Executor), protocolData
        );

        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.splitSwapPermit2(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            expAmountOut - 1,
            false,
            false,
            2,
            ALICE,
            permitSingle,
            signature,
            pleEncode(swaps)
        );

        uint256 finalBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertGe(finalBalance, expAmountOut);

        vm.stopPrank();
    }

    function testEmptySwapsRevert() public {
        uint256 amountIn = 10 ** 18;
        bytes memory swaps = "";
        vm.expectRevert(TychoRouter__EmptySwaps.selector);
        tychoRouter.exposedSplitSwap(amountIn, 2, swaps);
    }

    function testSplitSwapAmountInNotFullySpent() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // Has invalid data as input! There is only one swap with 60% of the input amount
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);

        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(WETH_ADDR, amountIn);

        bytes memory protocolData = encodeUniswapV2Swap(
            WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false
        );

        bytes memory swap = encodeSplitSwap(
            uint8(0),
            uint8(1),
            (0xffffff * 60) / 100, // 60%
            address(usv2Executor),
            protocolData
        );

        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        vm.expectRevert(
            abi.encodeWithSelector(
                TychoRouter__AmountInDiffersFromConsumed.selector,
                1000000000000000000,
                600000000000000000
            )
        );

        tychoRouter.splitSwapPermit2(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            1,
            false,
            false,
            2,
            ALICE,
            permitSingle,
            signature,
            pleEncode(swaps)
        );

        vm.stopPrank();
    }

    function testSplitSwapSingleUSV4Callback() public {
        uint256 amountIn = 100 ether;
        deal(USDE_ADDR, tychoRouterAddr, amountIn);

        UniswapV4Executor.UniswapV4Pool[] memory pools =
            new UniswapV4Executor.UniswapV4Pool[](1);
        pools[0] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: USDT_ADDR,
            fee: uint24(100),
            tickSpacing: int24(1)
        });

        bytes memory protocolData = UniswapV4Utils.encodeExactInput(
            USDE_ADDR, USDT_ADDR, true, address(usv4Executor), pools
        );

        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv4Executor), protocolData
        );

        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.exposedSplitSwap(amountIn, 2, pleEncode(swaps));

        assertEq(IERC20(USDT_ADDR).balanceOf(tychoRouterAddr), 99943852);
    }

    function testSplitSwapSingleUSV4CallbackPermit2() public {
        vm.startPrank(ALICE);
        uint256 amountIn = 100 ether;
        deal(USDE_ADDR, ALICE, amountIn);
        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(USDE_ADDR, amountIn);

        UniswapV4Executor.UniswapV4Pool[] memory pools =
            new UniswapV4Executor.UniswapV4Pool[](1);
        pools[0] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: USDT_ADDR,
            fee: uint24(100),
            tickSpacing: int24(1)
        });

        bytes memory protocolData = UniswapV4Utils.encodeExactInput(
            USDE_ADDR, USDT_ADDR, true, address(usv4Executor), pools
        );

        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv4Executor), protocolData
        );

        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.splitSwapPermit2(
            amountIn,
            USDE_ADDR,
            USDT_ADDR,
            99943850,
            false,
            false,
            2,
            ALICE,
            permitSingle,
            signature,
            pleEncode(swaps)
        );

        assertEq(IERC20(USDT_ADDR).balanceOf(ALICE), 99943852);
        vm.stopPrank();
    }

    function testSplitSwapMultipleUSV4Callback() public {
        // This test has two uniswap v4 hops that will be executed inside of the V4 pool manager
        // USDE -> USDT -> WBTC
        uint256 amountIn = 100 ether;
        deal(USDE_ADDR, tychoRouterAddr, amountIn);

        UniswapV4Executor.UniswapV4Pool[] memory pools =
            new UniswapV4Executor.UniswapV4Pool[](2);
        pools[0] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: USDT_ADDR,
            fee: uint24(100),
            tickSpacing: int24(1)
        });
        pools[1] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: WBTC_ADDR,
            fee: uint24(3000),
            tickSpacing: int24(60)
        });

        bytes memory protocolData = UniswapV4Utils.encodeExactInput(
            USDE_ADDR, WBTC_ADDR, true, address(usv4Executor), pools
        );

        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv4Executor), protocolData
        );

        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.exposedSplitSwap(amountIn, 2, pleEncode(swaps));

        assertEq(IERC20(WBTC_ADDR).balanceOf(tychoRouterAddr), 102718);
    }

    function testCyclicSequentialSwap() public {
        // This test has start and end tokens that are the same
        // The flow is:
        // USDC -> WETH -> USDC  using two pools
        uint256 amountIn = 100 * 10 ** 6;
        deal(USDC_ADDR, tychoRouterAddr, amountIn);

        bytes memory usdcWethV3Pool1ZeroOneData = encodeUniswapV3Swap(
            USDC_ADDR, WETH_ADDR, tychoRouterAddr, USDC_WETH_USV3, true
        );

        bytes memory usdcWethV3Pool2OneZeroData = encodeUniswapV3Swap(
            WETH_ADDR, USDC_ADDR, tychoRouterAddr, USDC_WETH_USV3_2, false
        );

        bytes[] memory swaps = new bytes[](2);
        // USDC -> WETH
        swaps[0] = encodeSplitSwap(
            uint8(0),
            uint8(1),
            uint24(0),
            address(usv3Executor),
            usdcWethV3Pool1ZeroOneData
        );
        // WETH -> USDC
        swaps[1] = encodeSplitSwap(
            uint8(1),
            uint8(0),
            uint24(0),
            address(usv3Executor),
            usdcWethV3Pool2OneZeroData
        );

        tychoRouter.exposedSplitSwap(amountIn, 2, pleEncode(swaps));
        assertEq(IERC20(USDC_ADDR).balanceOf(tychoRouterAddr), 99889294);
    }

    function testSplitInputCyclicSwap() public {
        // This test has start and end tokens that are the same
        // The flow is:
        //            ┌─ (USV3, 60% split) ──> WETH ─┐
        //            │                              │
        // USDC ──────┤                              ├──(USV2)──> USDC
        //            │                              │
        //            └─ (USV3, 40% split) ──> WETH ─┘
        uint256 amountIn = 100 * 10 ** 6;
        deal(USDC_ADDR, tychoRouterAddr, amountIn);

        bytes memory usdcWethV3Pool1ZeroOneData = encodeUniswapV3Swap(
            USDC_ADDR, WETH_ADDR, tychoRouterAddr, USDC_WETH_USV3, true
        );

        bytes memory usdcWethV3Pool2ZeroOneData = encodeUniswapV3Swap(
            USDC_ADDR, WETH_ADDR, tychoRouterAddr, USDC_WETH_USV3_2, true
        );

        bytes memory wethUsdcV2OneZeroData = encodeUniswapV2Swap(
            WETH_ADDR, USDC_WETH_USV2, tychoRouterAddr, false
        );

        bytes[] memory swaps = new bytes[](3);
        // USDC -> WETH (60% split)
        swaps[0] = encodeSplitSwap(
            uint8(0),
            uint8(1),
            (0xffffff * 60) / 100, // 60%
            address(usv3Executor),
            usdcWethV3Pool1ZeroOneData
        );
        // USDC -> WETH (40% remainder)
        swaps[1] = encodeSplitSwap(
            uint8(0),
            uint8(1),
            uint24(0),
            address(usv3Executor),
            usdcWethV3Pool2ZeroOneData
        );
        // WETH -> USDC
        swaps[2] = encodeSplitSwap(
            uint8(1),
            uint8(0),
            uint24(0),
            address(usv2Executor),
            wethUsdcV2OneZeroData
        );
        tychoRouter.exposedSplitSwap(amountIn, 2, pleEncode(swaps));
        assertEq(IERC20(USDC_ADDR).balanceOf(tychoRouterAddr), 99574171);
    }

    function testSplitOutputCyclicSwap() public {
        // This test has start and end tokens that are the same
        // The flow is:
        //                        ┌─── (USV3, 60% split) ───┐
        //                        │                         │
        // USDC ──(USV2) ── WETH──|                         ├─> USDC
        //                        │                         │
        //                        └─── (USV3, 40% split) ───┘

        uint256 amountIn = 100 * 10 ** 6;
        deal(USDC_ADDR, tychoRouterAddr, amountIn);

        bytes memory usdcWethV2Data = encodeUniswapV2Swap(
            USDC_ADDR, USDC_WETH_USV2, tychoRouterAddr, true
        );

        bytes memory usdcWethV3Pool1OneZeroData = encodeUniswapV3Swap(
            WETH_ADDR, USDC_ADDR, tychoRouterAddr, USDC_WETH_USV3, false
        );

        bytes memory usdcWethV3Pool2OneZeroData = encodeUniswapV3Swap(
            WETH_ADDR, USDC_ADDR, tychoRouterAddr, USDC_WETH_USV3_2, false
        );

        bytes[] memory swaps = new bytes[](3);
        // USDC -> WETH
        swaps[0] = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), usdcWethV2Data
        );
        // WETH -> USDC
        swaps[1] = encodeSplitSwap(
            uint8(1),
            uint8(0),
            (0xffffff * 60) / 100,
            address(usv3Executor),
            usdcWethV3Pool1OneZeroData
        );

        // WETH -> USDC
        swaps[2] = encodeSplitSwap(
            uint8(1),
            uint8(0),
            uint24(0),
            address(usv3Executor),
            usdcWethV3Pool2OneZeroData
        );

        tychoRouter.exposedSplitSwap(amountIn, 2, pleEncode(swaps));
        assertEq(IERC20(USDC_ADDR).balanceOf(tychoRouterAddr), 99525908);
    }

    // Base Network Tests
    // Make sure to set the RPC_URL to base network
    function testSplitSwapSingleBase() public {
        vm.skip(true);
        vm.rollFork(26857267);
        uint256 amountIn = 10 * 10 ** 6;
        deal(BASE_USDC, tychoRouterAddr, amountIn);

        bytes memory protocolData = encodeUniswapV2Swap(
            BASE_USDC, USDC_MAG7_POOL, tychoRouterAddr, true
        );

        bytes memory swap = encodeSplitSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.exposedSplitSwap(amountIn, 2, pleEncode(swaps));
        assertGt(IERC20(BASE_MAG7).balanceOf(tychoRouterAddr), 1379830606);
    }
}
