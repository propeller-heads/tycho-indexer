// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {TychoRouter} from "@src/TychoRouter.sol";
import "./TychoRouterTestSetup.sol";

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

    function testSetExecutorValidRole() public {
        // Set single executor
        address[] memory executors = new address[](1);
        executors[0] = DUMMY;
        vm.startPrank(EXECUTOR_SETTER);
        tychoRouter.batchSetExecutor(executors);
        vm.stopPrank();
        assert(tychoRouter.executors(DUMMY) == true);
    }

    function testSetExecutorMultipleValidRole() public {
        // Set multiple executors
        address[] memory executors = new address[](2);
        executors[0] = DUMMY;
        executors[1] = DUMMY2;
        vm.startPrank(EXECUTOR_SETTER);
        tychoRouter.batchSetExecutor(executors);
        vm.stopPrank();
        assert(tychoRouter.executors(DUMMY) == true);
        assert(tychoRouter.executors(DUMMY2) == true);
    }

    function testRemoveExecutorValidRole() public {
        vm.startPrank(EXECUTOR_SETTER);
        address[] memory executors = new address[](1);
        executors[0] = DUMMY;
        tychoRouter.batchSetExecutor(executors);
        tychoRouter.removeExecutor(DUMMY);
        vm.stopPrank();
        assert(tychoRouter.executors(DUMMY) == false);
    }

    function testRemoveExecutorMissingSetterRole() public {
        vm.expectRevert();
        tychoRouter.removeExecutor(BOB);
    }

    function testSetExecutorMissingSetterRole() public {
        vm.expectRevert();
        address[] memory executors = new address[](1);
        executors[0] = DUMMY;
        tychoRouter.batchSetExecutor(executors);
    }

    function testSetVerifierValidRole() public {
        vm.startPrank(EXECUTOR_SETTER);
        tychoRouter.setCallbackVerifier(DUMMY);
        vm.stopPrank();
        assert(tychoRouter.callbackVerifiers(DUMMY) == true);
    }

    function testRemoveVerifierValidRole() public {
        vm.startPrank(EXECUTOR_SETTER);
        tychoRouter.setCallbackVerifier(DUMMY);
        tychoRouter.removeCallbackVerifier(DUMMY);
        vm.stopPrank();
        assert(tychoRouter.callbackVerifiers(DUMMY) == false);
    }

    function testRemoveVerifierMissingSetterRole() public {
        vm.expectRevert();
        tychoRouter.removeCallbackVerifier(BOB);
    }

    function testSetVerifierMissingSetterRole() public {
        vm.expectRevert();
        tychoRouter.setCallbackVerifier(DUMMY);
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
        // TODO: test swap calls when implemeted
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
        //       (univ2)
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, tychoRouterAddr, amountIn);

        bytes memory protocolData = encodeUniswapV2Swap(
            WETH_ADDR, WETH_DAI_POOL, tychoRouterAddr, false
        );

        bytes memory swap = encodeSwap(
            uint8(0),
            uint8(1),
            uint24(0),
            address(usv2Executor),
            bytes4(0),
            protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.exposedSwap(amountIn, 2, pleEncode(swaps));

        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(tychoRouterAddr);
        assertEq(daiBalance, 2630432278145144658455);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
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
            bytes4(0),
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
            bytes4(0),
            encodeUniswapV2Swap(DAI_ADDR, DAI_USDC_POOL, tychoRouterAddr, true)
        );

        tychoRouter.exposedSwap(amountIn, 3, pleEncode(swaps));

        uint256 usdcBalance = IERC20(USDC_ADDR).balanceOf(tychoRouterAddr);
        assertEq(usdcBalance, 2610580090);
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
            bytes4(0),
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
            bytes4(0),
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
            bytes4(0),
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
            bytes4(0),
            encodeUniswapV2Swap(DAI_ADDR, DAI_USDC_POOL, tychoRouterAddr, true)
        );

        tychoRouter.exposedSwap(amountIn, 4, pleEncode(swaps));

        uint256 usdcBalance = IERC20(USDC_ADDR).balanceOf(tychoRouterAddr);
        assertEq(usdcBalance, 2581503157);
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
            uint8(0),
            uint8(1),
            uint24(0),
            address(usv2Executor),
            bytes4(0),
            protocolData
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
            permitSingle,
            signature,
            pleEncode(swaps)
        );

        uint256 expectedAmount = 2630432278145144658455;
        assertEq(amountOut, expectedAmount);
        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertEq(daiBalance, expectedAmount);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), 0);

        vm.stopPrank();
    }

    function testSwapCheckedFailure() public {
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
            uint8(0),
            uint8(1),
            uint24(0),
            address(usv2Executor),
            bytes4(0),
            protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        uint256 minAmountOut = 3000 * 1e18;
        vm.expectRevert(
            abi.encodeWithSelector(
                TychoRouter__NegativeSlippage.selector,
                2630432278145144658455, // actual amountOut
                minAmountOut
            )
        );
        tychoRouter.swap(
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
            uint8(0),
            uint8(1),
            uint24(0),
            address(usv2Executor),
            bytes4(0),
            protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        uint256 amountOut = tychoRouter.swap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            0,
            false,
            false,
            2,
            ALICE,
            permitSingle,
            signature,
            pleEncode(swaps)
        );

        uint256 expectedAmount = 2604127955363693211871;
        assertEq(amountOut, expectedAmount);
        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertEq(daiBalance, expectedAmount);
        assertEq(IERC20(DAI_ADDR).balanceOf(FEE_RECEIVER), 26304322781451446584);

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
            uint8(0),
            uint8(1),
            uint24(0),
            address(usv2Executor),
            bytes4(0),
            protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        uint256 amountOut = tychoRouter.swap{value: amountIn}(
            amountIn,
            address(0),
            DAI_ADDR,
            0,
            true,
            false,
            2,
            ALICE,
            emptyPermitSingle,
            "",
            pleEncode(swaps)
        );
        uint256 expectedAmount = 2630432278145144658455;
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
            uint8(0),
            uint8(1),
            uint24(0),
            address(usv2Executor),
            bytes4(0),
            protocolData
        );
        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        uint256 amountOut = tychoRouter.swap(
            amountIn,
            DAI_ADDR,
            address(0),
            0,
            false,
            true,
            2,
            ALICE,
            permitSingle,
            signature,
            pleEncode(swaps)
        );

        uint256 expectedAmount = 1132829934891544187; // 1.13 ETH
        assertEq(amountOut, expectedAmount);
        assertEq(ALICE.balance, expectedAmount);

        vm.stopPrank();
    }
}
