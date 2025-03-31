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

    function testSwapSimple() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // 1 WETH   ->   DAI
        //       (USV2)
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, tychoRouterAddr, amountIn);

        bytes memory protocolData = encodeUniswapV2Swap(
            WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false
        );

        bytes memory swap = encodeSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.exposedSwap(amountIn, 2, pleEncode(swaps));

        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(tychoRouterAddr);
        assertEq(daiBalance, 2659881924818443699787);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testSwapSimplePermit2() public {
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

        bytes memory swap = encodeSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.swapPermit2(
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

    function testSwapMultipleHops() public {
        // Trade 1 WETH for USDC through DAI with 2 swaps on Uniswap V2
        // 1 WETH   ->   DAI   ->   USDC
        //       (univ2)     (univ2)
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, tychoRouterAddr, amountIn);

        bytes[] memory swaps = new bytes[](2);
        // WETH -> DAI
        swaps[0] = encodeSwap(
            uint8(0),
            uint8(1),
            uint24(0),
            address(usv2Executor),
            encodeUniswapV2Swap(
                WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false
            )
        );

        // DAI -> USDC
        swaps[1] = encodeSwap(
            uint8(1),
            uint8(2),
            uint24(0),
            address(usv2Executor),
            encodeUniswapV2Swap(DAI_ADDR, DAI_USDC_POOL, tychoRouterAddr, true)
        );

        tychoRouter.exposedSwap(amountIn, 3, pleEncode(swaps));

        uint256 usdcBalance = IERC20(USDC_ADDR).balanceOf(tychoRouterAddr);
        assertEq(usdcBalance, 2644659787);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testSwapSplitHops() public {
        // Trade 1 WETH for USDC through DAI and WBTC with 4 swaps on Uniswap V2
        //          ->   DAI   ->
        // 1 WETH                   USDC
        //          ->   WBTC  ->
        //       (univ2)     (univ2)
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, tychoRouterAddr, amountIn);

        bytes[] memory swaps = new bytes[](4);
        // WETH -> WBTC (60%)
        swaps[0] = encodeSwap(
            uint8(0),
            uint8(1),
            (0xffffff * 60) / 100, // 60%
            address(usv2Executor),
            encodeUniswapV2Swap(
                WETH_ADDR, WETH_WBTC_POOL, tychoRouterAddr, false
            )
        );
        // WBTC -> USDC
        swaps[1] = encodeSwap(
            uint8(1),
            uint8(2),
            uint24(0),
            address(usv2Executor),
            encodeUniswapV2Swap(
                WBTC_ADDR, USDC_WBTC_POOL, tychoRouterAddr, true
            )
        );
        // WETH -> DAI
        swaps[2] = encodeSwap(
            uint8(0),
            uint8(3),
            uint24(0),
            address(usv2Executor),
            encodeUniswapV2Swap(
                WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false
            )
        );

        // DAI -> USDC
        swaps[3] = encodeSwap(
            uint8(3),
            uint8(2),
            uint24(0),
            address(usv2Executor),
            encodeUniswapV2Swap(DAI_ADDR, DAI_USDC_POOL, tychoRouterAddr, true)
        );

        tychoRouter.exposedSwap(amountIn, 4, pleEncode(swaps));

        uint256 usdcBalance = IERC20(USDC_ADDR).balanceOf(tychoRouterAddr);
        assertEq(usdcBalance, 2615491639);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testSwapChecked() public {
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

        bytes memory swap = encodeSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        uint256 minAmountOut = 2600 * 1e18;
        uint256 amountOut = tychoRouter.swapPermit2(
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

    function testSwapCheckedUndefinedMinAmount() public {
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

        bytes memory swap = encodeSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;
        uint256 minAmountOut = 0;

        vm.expectRevert(TychoRouter__UndefinedMinAmountOut.selector);
        tychoRouter.swapPermit2(
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

    function testSwapCheckedNoPermit2() public {
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

        bytes memory swap = encodeSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        uint256 minAmountOut = 2600 * 1e18;
        uint256 amountOut = tychoRouter.swap(
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

    function testSwapCheckedLessApprovalFailure() public {
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

        bytes memory swap = encodeSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        uint256 minAmountOut = 2600 * 1e18;
        vm.expectRevert();
        tychoRouter.swap(
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

    function testSwapCheckedNegativeSlippageFailure() public {
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

        bytes memory swap = encodeSwap(
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
        tychoRouter.swapPermit2(
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

    function testSwapFee() public {
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

        bytes memory swap = encodeSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        uint256 amountOut = tychoRouter.swapPermit2(
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

    function testSwapWrapETH() public {
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

        bytes memory swap = encodeSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        uint256 amountOut = tychoRouter.swapPermit2{value: amountIn}(
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

    function testSwapUnwrapETH() public {
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

        bytes memory swap = encodeSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        uint256 amountOut = tychoRouter.swapPermit2(
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

    function testSwapSingleUSV3() public {
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
        bytes memory swap = encodeSwap(
            uint8(0), uint8(1), uint24(0), address(usv3Executor), protocolData
        );

        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.exposedSwap(amountIn, 2, pleEncode(swaps));

        uint256 finalBalance = IERC20(DAI_ADDR).balanceOf(tychoRouterAddr);
        assertGe(finalBalance, expAmountOut);
    }

    function testSwapSinglePancakeV3() public {
        // Trade 1 WETH for USDT with 1 swap on Pancakeswap V3
        // 1 WETH    ->    USDT
        //       (PancakeV3)
        uint256 amountIn = 10 ** 18;
        deal(WETH_ADDR, tychoRouterAddr, amountIn);

        uint256 expAmountOut = 2659_567519; //Swap 1 WETH for 1205.12 DAI
        bool zeroForOne = true;
        bytes memory protocolData = encodeUniswapV3Swap(
            WETH_ADDR,
            USDT_ADDR,
            tychoRouterAddr,
            PANCAKESWAPV3_WETH_USDT_POOL,
            zeroForOne
        );
        bytes memory swap = encodeSwap(
            uint8(0),
            uint8(1),
            uint24(0),
            address(pancakev3Executor),
            protocolData
        );

        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.exposedSwap(amountIn, 2, pleEncode(swaps));

        uint256 finalBalance = IERC20(USDT_ADDR).balanceOf(tychoRouterAddr);
        assertGe(finalBalance, expAmountOut);
    }

    function testSwapSingleUSV3Permit2() public {
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
        bytes memory swap = encodeSwap(
            uint8(0), uint8(1), uint24(0), address(usv3Executor), protocolData
        );

        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.swapPermit2(
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
        tychoRouter.exposedSwap(amountIn, 2, swaps);
    }

    function testSingleSwapIntegration() public {
        // Test created with calldata from our router encoder, replacing the executor
        // address with the USV2 executor address.

        // Tests swapping WETH -> DAI on a USV2 pool
        deal(WETH_ADDR, ALICE, 1 ether);
        uint256 balancerBefore = IERC20(DAI_ADDR).balanceOf(ALICE);

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);
        // Encoded solution generated using `test_split_swap_strategy_encoder_simple`
        // but manually replacing the executor address
        // `5c2f5a71f67c01775180adc06909288b4c329308` with the one in this test
        // `5615deb798bb3e4dfa0139dfa1b3d433cc23b72f`
        (bool success,) = tychoRouterAddr.call(
            hex"d499aa880000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000006b175474e89094c44da98b954eedeac495271d0f0000000000000000000000000000000000000000000000903146e5f6c59c064b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000067e4225a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ede3eca2a72b3aecc820e955b36f38437d013950000000000000000000000000000000000000000000000000000000067bc9c620000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000000411fdbe0ac6bdafd51044f24b158235effa29797f468cd4684efa379053d3d15d47ed8b8206e3f6e7349f40aad231cc7e04ed25cbea1ac659b575be8cc168fc2361c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000058005600010000005615deb798bb3e4dfa0139dfa1b3d433cc23b72fc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a478c2975ab1ea89e8196811f51a7b7ade33eb113ede3eca2a72b3aecc820e955b36f38437d01395000000000000000000"
        );

        vm.stopPrank();

        uint256 balancerAfter = IERC20(DAI_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertEq(balancerAfter - balancerBefore, 2659881924818443699787);
    }

    function testSingleSwapWithoutPermit2Integration() public {
        // Test created with calldata from our router encoder, replacing the executor
        // address with the USV2 executor address.

        // Tests swapping WETH -> DAI on a USV2 pool without permit2
        deal(WETH_ADDR, ALICE, 1 ether);
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), 1 ether);
        uint256 balancerBefore = IERC20(DAI_ADDR).balanceOf(ALICE);
        // Encoded solution generated using `test_split_swap_strategy_encoder_simple_route_no_permit2`
        // but manually replacing the executor address
        // `5c2f5a71f67c01775180adc06909288b4c329308` with the one in this test
        // `5615deb798bb3e4dfa0139dfa1b3d433cc23b72f`
        (bool success,) = tychoRouterAddr.call(
            hex"0a83cb080000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000006b175474e89094c44da98b954eedeac495271d0f00000000000000000000000000000000000000000000008f1d5c1cae37400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc200000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000058005600010000005615deb798bb3e4dfa0139dfa1b3d433cc23b72fc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a478c2975ab1ea89e8196811f51a7b7ade33eb113ede3eca2a72b3aecc820e955b36f38437d01395000000000000000000"
        );

        vm.stopPrank();
        uint256 balancerAfter = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertTrue(success, "Call Failed");
        assertEq(balancerAfter - balancerBefore, 2659881924818443699787);
    }

    function testUSV4Integration() public {
        // Test created with calldata from our router encoder.

        // Performs a sequential swap from USDC to PEPE though ETH using two
        // consecutive USV4 pools
        //
        //   USDC ──(USV4)──> ETH ───(USV4)──> PEPE
        //
        deal(USDC_ADDR, ALICE, 1 ether);
        uint256 balancerBefore = IERC20(PEPE_ADDR).balanceOf(ALICE);

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);
        // Encoded solution generated using `test_split_encoding_strategy_usv4`
        // and ensuring that the encoded executor address is the one in this test
        // `f62849f9a0b5bf2913b396098f7c7019b51a820a`
        (bool success,) = tychoRouterAddr.call(
            hex"d499aa88000000000000000000000000000000000000000000000000000000003b9aca00000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000006982508145454ce325ddbe47a25d4ec3d23119330000000000000000000000000000000000000000005064ff624d54346285543f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000000000000000000000000000000000003b9aca000000000000000000000000000000000000000000000000000000000067e4237600000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ede3eca2a72b3aecc820e955b36f38437d013950000000000000000000000000000000000000000000000000000000067bc9d7e00000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000004166b5d3bb274c323e08eeba45d308cc9c11216f9aaafad2a22e94b94fec39293e5480f65f6238d7c8f1e8177f39118373e1041b0ab3a674d3041d119bdb6bc39c1b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008c008a0001000000f62849f9a0b5bf2913b396098f7c7019b51a820aa0b86991c6218b36c1d19d4a2e9eb0ce3606eb486982508145454ce325ddbe47a25d4ec3d231193300f62849f9a0b5bf2913b396098f7c7019b51a820a0000000000000000000000000000000000000000000bb800003c6982508145454ce325ddbe47a25d4ec3d23119330061a80001f40000000000000000000000000000000000000000"
        );

        vm.stopPrank();

        uint256 balancerAfter = IERC20(PEPE_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertEq(balancerAfter - balancerBefore, 97191013220606467325121599);
    }

    function testUSV4IntegrationInputETH() public {
        // Test created with calldata from our router encoder.

        // Performs a single swap from ETH to PEPE without wrapping or unwrapping
        //
        //   ETH ───(USV4)──> PEPE
        //
        deal(ALICE, 1 ether);
        uint256 balancerBefore = IERC20(PEPE_ADDR).balanceOf(ALICE);

        // Encoded solution generated using `test_split_encoding_strategy_usv4_eth_in`
        // and ensuring that the encoded executor address is the one in this test
        // `f62849f9a0b5bf2913b396098f7c7019b51a820a`
        (bool success,) = tychoRouterAddr.call{value: 1 ether}(
            hex"d499aa880000000000000000000000000000000000000000000000000de0b6b3a764000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006982508145454ce325ddbe47a25d4ec3d2311933000000000000000000000000000000000000000000c87c939ae635f92dc2379c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000067f01a7800000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ede3eca2a72b3aecc820e955b36f38437d013950000000000000000000000000000000000000000000000000000000067c894800000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000000416642950b804a47a0abcb17d81cc2a7967d606e00e8de470e0e7827347658160a28b9892f147248b9bf31aad8faa06181aee0c4a612151e9ef4889991b9930b791b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007200700001000000f62849f9a0b5bf2913b396098f7c7019b51a820a00000000000000000000000000000000000000006982508145454ce325ddbe47a25d4ec3d231193301f62849f9a0b5bf2913b396098f7c7019b51a820a6982508145454ce325ddbe47a25d4ec3d23119330061a80001f40000000000000000000000000000"
        );

        vm.stopPrank();

        uint256 balancerAfter = IERC20(PEPE_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertEq(balancerAfter - balancerBefore, 242373460199848577067005852);
    }

    function testUSV4IntegrationOutputETH() public {
        // Test created with calldata from our router encoder.

        // Performs a single swap from USDC to ETH without wrapping or unwrapping
        //
        //   USDC ───(USV4)──> ETH
        //
        deal(USDC_ADDR, ALICE, 3000_000000);
        uint256 balancerBefore = ALICE.balance;

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);

        // Encoded solution generated using `test_split_encoding_strategy_usv4_eth_out`
        // and ensuring that the encoded executor address is the one in this test
        // `f62849f9a0b5bf2913b396098f7c7019b51a820a`
        (bool success,) = tychoRouterAddr.call(
            hex"d499aa8800000000000000000000000000000000000000000000000000000000b2d05e00000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f81490b4f29aade000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000b2d05e000000000000000000000000000000000000000000000000000000000067f01af000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ede3eca2a72b3aecc820e955b36f38437d013950000000000000000000000000000000000000000000000000000000067c894f80000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000000417811cd10b02278128a9e4df9ef2e099cff6ad46ec6ead5ba0b70dd1db5749d573cf4a8821a524bd6cc5b61ce0faf69d1d4b1f9233b93a4b203e79668f250b1a71c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007200700001000000f62849f9a0b5bf2913b396098f7c7019b51a820aa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000000000000000000000f62849f9a0b5bf2913b396098f7c7019b51a820a0000000000000000000000000000000000000000000bb800003c0000000000000000000000000000"
        );

        vm.stopPrank();

        uint256 balancerAfter = ALICE.balance;

        assertTrue(success, "Call Failed");
        console.logUint(balancerAfter - balancerBefore);
        assertEq(balancerAfter - balancerBefore, 1117254495486192350);
    }

    function testSingleSwapWithWrapIntegration() public {
        // Test created with calldata from our router encoder, replacing the executor
        // address with the USV2 executor address.

        // Tests swapping WETH -> DAI on a USV2 pool, but ETH is received from the user
        // and wrapped before the swap
        deal(ALICE, 1 ether);
        uint256 balancerBefore = IERC20(DAI_ADDR).balanceOf(ALICE);

        // Approve permit2
        vm.startPrank(ALICE);
        // Encoded solution generated using
        // `test_split_swap_strategy_encoder_simple_route_wrap`
        // but manually replacing the executor address
        // `f6c5be66fff9dc69962d73da0a617a827c382329` with the one in this test
        // `5615deb798bb3e4dfa0139dfa1b3d433cc23b72f`
        (bool success,) = tychoRouterAddr.call{value: 1 ether}(
            hex"d499aa880000000000000000000000000000000000000000000000000de0b6b3a764000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006b175474e89094c44da98b954eedeac495271d0f0000000000000000000000000000000000000000000000903146e5f6c59c064b000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000067f0192a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ede3eca2a72b3aecc820e955b36f38437d013950000000000000000000000000000000000000000000000000000000067c893320000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000000419849ede1f59ad3092a3d8f6b5d7a4d3d854c8013d0a728b8556dc9744ddeed6c7edc4987c7724c280d493ca8dd55dd5aa5f5a66a66d85683f8a5b744908752a21b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000058005600020000005615deb798bb3e4dfa0139dfa1b3d433cc23b72fc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a478c2975ab1ea89e8196811f51a7b7ade33eb113ede3eca2a72b3aecc820e955b36f38437d01395000000000000000000"
        );

        vm.stopPrank();

        uint256 balancerAfter = IERC20(DAI_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertEq(balancerAfter - balancerBefore, 2659881924818443699787);
    }

    function testSingleSwapWithUnwrapIntegration() public {
        // Test created with calldata from our router encoder, replacing the executor
        // address with the USV2 executor address.

        // Tests swapping DAI -> WETH on a USV2 pool, and WETH is unwrapped to ETH
        // before sending back to the user
        deal(DAI_ADDR, ALICE, 3000 ether);
        uint256 balancerBefore = ALICE.balance;

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(DAI_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);
        // Encoded solution generated using
        // `test_split_swap_strategy_encoder_simple_route_unwrap`
        // but manually replacing the executor address
        // `f6c5be66fff9dc69962d73da0a617a827c382329` with the one in this test
        // `5615deb798bb3e4dfa0139dfa1b3d433cc23b72f`
        (bool success,) = tychoRouterAddr.call(
            hex"d499aa880000000000000000000000000000000000000000000000a2a15d09519be000000000000000000000000000006b175474e89094c44da98b954eedeac495271d0f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000dbd2fc137a30000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc20000000000000000000000006b175474e89094c44da98b954eedeac495271d0f0000000000000000000000000000000000000000000000a2a15d09519be000000000000000000000000000000000000000000000000000000000000067f017d700000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ede3eca2a72b3aecc820e955b36f38437d013950000000000000000000000000000000000000000000000000000000067c891df00000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000004181b0d9c7bbf7bd3270e22a7ff337b019b006ea60d9e357035b622bfc8e48126343fa9c1342383d3d072c2ddea2072fd5e447e7b6a4b56f5e7973963d18664e5d1b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000058005600010000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f6b175474e89094c44da98b954eedeac495271d0fa478c2975ab1ea89e8196811f51a7b7ade33eb113ede3eca2a72b3aecc820e955b36f38437d01395010000000000000000"
        );

        vm.stopPrank();

        uint256 balancerAfter = ALICE.balance;

        assertTrue(success, "Call Failed");
        assertEq(balancerAfter - balancerBefore, 1120007305574805922);
    }

    function testSplitSwapIntegration() public {
        // Test created with calldata from our router encoder, replacing the executor
        // address with the USV2 executor address.

        // Performs a split swap from WETH to USDC though WBTC and DAI using USV2 pools
        //
        //         ┌──(USV2)──> WBTC ───(USV2)──> USDC
        //   WETH ─┤
        //         └──(USV2)──> DAI  ───(USV2)──> USDC
        deal(WETH_ADDR, ALICE, 1 ether);
        uint256 balancerBefore = IERC20(USDC_ADDR).balanceOf(ALICE);

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);
        // Encoded solution generated using `test_split_swap_strategy_encoder_complex`
        // but manually replacing the executor address
        // `f6c5be66FFf9DC69962d73da0A617a827c382329` with the one in this test
        // `5615deb798bb3e4dfa0139dfa1b3d433cc23b72f`
        (bool success,) = tychoRouterAddr.call(
            hex"d499aa880000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000018f61ec000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000067f0198700000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ede3eca2a72b3aecc820e955b36f38437d013950000000000000000000000000000000000000000000000000000000067c8938f000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000041308a3ba881e23ac794deca324cfd959b808c86bb239b81c9db8873c8392382411f87902e6ceb8e59636d8d6fab4ead1863727f9a2168246c93b678f3ae4ae37b1b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000160005600028000005615deb798bb3e4dfa0139dfa1b3d433cc23b72fc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a478c2975ab1ea89e8196811f51a7b7ade33eb113ede3eca2a72b3aecc820e955b36f38437d0139500005600010000005615deb798bb3e4dfa0139dfa1b3d433cc23b72fc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2bb2b8038a1640196fbe3e38816f3e67cba72d9403ede3eca2a72b3aecc820e955b36f38437d0139500005602030000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f6b175474e89094c44da98b954eedeac495271d0fae461ca67b15dc8dc81ce7615e0320da1a9ab8d53ede3eca2a72b3aecc820e955b36f38437d0139501005601030000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f2260fac5e5542a773aa44fbcfedf7c193bc2c599004375dff511095cc5a197a54140a24efef3a4163ede3eca2a72b3aecc820e955b36f38437d0139501"
        );

        vm.stopPrank();

        uint256 balancerAfter = IERC20(USDC_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertGe(balancerAfter - balancerBefore, 26173932);

        // All input tokens are transferred to the router at first. Make sure we used
        // all of it (and thus our splits are correct).
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }

    function testSwapAmountInNotFullySpent() public {
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

        bytes memory swap = encodeSwap(
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

        tychoRouter.swapPermit2(
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

    function testSwapSingleUSV4Callback() public {
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

        bytes memory swap = encodeSwap(
            uint8(0), uint8(1), uint24(0), address(usv4Executor), protocolData
        );

        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.exposedSwap(amountIn, 2, pleEncode(swaps));

        assertEq(IERC20(USDT_ADDR).balanceOf(tychoRouterAddr), 99943852);
    }

    function testSwapSingleUSV4CallbackPermit2() public {
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

        bytes memory swap = encodeSwap(
            uint8(0), uint8(1), uint24(0), address(usv4Executor), protocolData
        );

        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.swapPermit2(
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

    function testSwapMultipleUSV4Callback() public {
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

        bytes memory swap = encodeSwap(
            uint8(0), uint8(1), uint24(0), address(usv4Executor), protocolData
        );

        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.exposedSwap(amountIn, 2, pleEncode(swaps));

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
        swaps[0] = encodeSwap(
            uint8(0),
            uint8(1),
            uint24(0),
            address(usv3Executor),
            usdcWethV3Pool1ZeroOneData
        );
        // WETH -> USDC
        swaps[1] = encodeSwap(
            uint8(1),
            uint8(0),
            uint24(0),
            address(usv3Executor),
            usdcWethV3Pool2OneZeroData
        );

        tychoRouter.exposedSwap(amountIn, 2, pleEncode(swaps));
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
        swaps[0] = encodeSwap(
            uint8(0),
            uint8(1),
            (0xffffff * 60) / 100, // 60%
            address(usv3Executor),
            usdcWethV3Pool1ZeroOneData
        );
        // USDC -> WETH (40% remainder)
        swaps[1] = encodeSwap(
            uint8(0),
            uint8(1),
            uint24(0),
            address(usv3Executor),
            usdcWethV3Pool2ZeroOneData
        );
        // WETH -> USDC
        swaps[2] = encodeSwap(
            uint8(1),
            uint8(0),
            uint24(0),
            address(usv2Executor),
            wethUsdcV2OneZeroData
        );
        tychoRouter.exposedSwap(amountIn, 2, pleEncode(swaps));
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
        swaps[0] = encodeSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), usdcWethV2Data
        );
        // WETH -> USDC
        swaps[1] = encodeSwap(
            uint8(1),
            uint8(0),
            (0xffffff * 60) / 100,
            address(usv3Executor),
            usdcWethV3Pool1OneZeroData
        );

        // WETH -> USDC
        swaps[2] = encodeSwap(
            uint8(1),
            uint8(0),
            uint24(0),
            address(usv3Executor),
            usdcWethV3Pool2OneZeroData
        );

        tychoRouter.exposedSwap(amountIn, 2, pleEncode(swaps));
        assertEq(IERC20(USDC_ADDR).balanceOf(tychoRouterAddr), 99525908);
    }

    function testCyclicSequentialSwapIntegration() public {
        deal(USDC_ADDR, ALICE, 100 * 10 ** 6);

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);
        // Encoded solution generated using `test_cyclic_sequential_swap`
        // but manually replacing the executor address
        // `dd8559c917393fc8dd2b4dd289c52ff445fde1b0` with the one in this test
        // `2e234dae75c793f67a35089c9d99245e1c58470b`
        (bool success,) = tychoRouterAddr.call(
            hex"d499aa880000000000000000000000000000000000000000000000000000000005f5e100000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000005f4308e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000005f5e1000000000000000000000000000000000000000000000000000000000067f67a8b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ede3eca2a72b3aecc820e955b36f38437d013950000000000000000000000000000000000000000000000000000000067cef493000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000041c07077fc73bb0f5129006061288fa0583c101631307377281d6b8f3feb50aa2d564f9948c92e0e4abc3771d592bd2f22ebb18ccf21b270459b05f272251ce1c71b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000de006d00010000002e234dae75c793f67a35089c9d99245e1c58470ba0b86991c6218b36c1d19d4a2e9eb0ce3606eb48c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20001f43ede3eca2a72b3aecc820e955b36f38437d0139588e6a0c2ddd26feeb64f039a2c41296fcb3f564001006d01000000002e234dae75c793f67a35089c9d99245e1c58470bc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000bb83ede3eca2a72b3aecc820e955b36f38437d013958ad599c3a0ff1de082011efddc58f1908eb6e6d8000000"
        );

        assertEq(IERC20(USDC_ADDR).balanceOf(ALICE), 99889294);

        vm.stopPrank();
    }

    function testSplitInputCyclicSwapIntegration() public {
        deal(USDC_ADDR, ALICE, 100 * 10 ** 6);

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);
        // Encoded solution generated using `test_split_input_cyclic_swap`
        // but manually replacing the executor addresses with the ones in this test
        // `dd8559c917393fc8dd2b4dd289c52ff445fde1b0` to `2e234dae75c793f67a35089c9d99245e1c58470b`
        // `f6c5be66fff9dc69962d73da0a617a827c382329` to `5615deb798bb3e4dfa0139dfa1b3d433cc23b72f`
        (bool success,) = tychoRouterAddr.call(
            hex"d499aa880000000000000000000000000000000000000000000000000000000005f5e100000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000005ef619b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000005f5e1000000000000000000000000000000000000000000000000000000000067f6c08700000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ede3eca2a72b3aecc820e955b36f38437d013950000000000000000000000000000000000000000000000000000000067cf3a8f000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000041f248bfa39e6801b4173cd4d61e5e5d0c31942eb3c194785f964a82b2c3e05b4b302bccc0924fa4c4ef90854e42865db11f458d3b6a62afddee833f3eb069cd521b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000136006d00019999992e234dae75c793f67a35089c9d99245e1c58470ba0b86991c6218b36c1d19d4a2e9eb0ce3606eb48c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20001f43ede3eca2a72b3aecc820e955b36f38437d0139588e6a0c2ddd26feeb64f039a2c41296fcb3f564001006d00010000002e234dae75c793f67a35089c9d99245e1c58470ba0b86991c6218b36c1d19d4a2e9eb0ce3606eb48c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000bb83ede3eca2a72b3aecc820e955b36f38437d013958ad599c3a0ff1de082011efddc58f1908eb6e6d801005601000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72fc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2b4e16d0168e52d35cacd2c6185b44281ec28c9dc3ede3eca2a72b3aecc820e955b36f38437d013950000000000000000000000"
        );

        assertEq(IERC20(USDC_ADDR).balanceOf(ALICE), 99574171);

        vm.stopPrank();
    }

    function testSplitOutputCyclicSwapIntegration() public {
        deal(USDC_ADDR, ALICE, 100 * 10 ** 6);

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);
        // Encoded solution generated using `test_split_output_cyclic_swap`
        // but manually replacing the executor addresses with the ones in this test
        // `dd8559c917393fc8dd2b4dd289c52ff445fde1b0` to `2e234dae75c793f67a35089c9d99245e1c58470b`
        // `f6c5be66fff9dc69962d73da0a617a827c382329` to `5615deb798bb3e4dfa0139dfa1b3d433cc23b72f`
        (bool success,) = tychoRouterAddr.call(
            hex"d499aa880000000000000000000000000000000000000000000000000000000005f5e100000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000005eea514000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000005f5e1000000000000000000000000000000000000000000000000000000000067f6be9400000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ede3eca2a72b3aecc820e955b36f38437d013950000000000000000000000000000000000000000000000000000000067cf389c000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000041c02ad8eceede50085f35ce8e8313ebbac9b379396c6e72a35bb4df0970cbdaaa1a91e6f787641af55b13b926199c844df42fdd2ae7bb287db7e5cc2a8bc1d7f51b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000136005600010000005615deb798bb3e4dfa0139dfa1b3d433cc23b72fa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48b4e16d0168e52d35cacd2c6185b44281ec28c9dc3ede3eca2a72b3aecc820e955b36f38437d0139501006d01009999992e234dae75c793f67a35089c9d99245e1c58470bc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480001f43ede3eca2a72b3aecc820e955b36f38437d0139588e6a0c2ddd26feeb64f039a2c41296fcb3f564000006d01000000002e234dae75c793f67a35089c9d99245e1c58470bc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000bb83ede3eca2a72b3aecc820e955b36f38437d013958ad599c3a0ff1de082011efddc58f1908eb6e6d80000000000000000000000"
        );

        assertEq(IERC20(USDC_ADDR).balanceOf(ALICE), 99525908);

        vm.stopPrank();
    }

    // Base Network Tests
    // Make sure to set the RPC_URL to base network
    function testSwapSingleBase() public {
        vm.skip(true);
        vm.rollFork(26857267);
        uint256 amountIn = 10 * 10 ** 6;
        deal(BASE_USDC, tychoRouterAddr, amountIn);

        bytes memory protocolData = encodeUniswapV2Swap(
            BASE_USDC, USDC_MAG7_POOL, tychoRouterAddr, true
        );

        bytes memory swap = encodeSwap(
            uint8(0), uint8(1), uint24(0), address(usv2Executor), protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.exposedSwap(amountIn, 2, pleEncode(swaps));
        assertGt(IERC20(BASE_MAG7).balanceOf(tychoRouterAddr), 1379830606);
    }
}
