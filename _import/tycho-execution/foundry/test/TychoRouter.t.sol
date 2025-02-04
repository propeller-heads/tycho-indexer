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
        //       (USV2)
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

    function testUSV3Callback() public {
        uint24 poolFee = 3000;
        uint256 amountOwed = 1000000000000000000;
        deal(WETH_ADDR, tychoRouterAddr, amountOwed);
        uint256 initialPoolReserve = IERC20(WETH_ADDR).balanceOf(DAI_WETH_USV3);

        vm.startPrank(DAI_WETH_USV3);
        tychoRouter.uniswapV3SwapCallback(
            -2631245338449998525223,
            int256(amountOwed),
            abi.encodePacked(WETH_ADDR, DAI_ADDR, poolFee)
        );
        vm.stopPrank();

        uint256 finalPoolReserve = IERC20(WETH_ADDR).balanceOf(DAI_WETH_USV3);
        assertEq(finalPoolReserve - initialPoolReserve, amountOwed);
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
            uint8(0),
            uint8(1),
            uint24(0),
            address(usv3Executor),
            bytes4(0),
            protocolData
        );

        bytes[] memory swaps = new bytes[](1);
        swaps[0] = swap;

        tychoRouter.exposedSwap(amountIn, 2, pleEncode(swaps));

        uint256 finalBalance = IERC20(DAI_ADDR).balanceOf(tychoRouterAddr);
        assertGe(finalBalance, expAmountOut);
    }

    function testSingleSwapIntegration() public {
        // Test created with calldata from our router encoder, replacing the executor
        // address with the USV2 executor address.

        // Tests swapping WETH -> DAI on a USV2 pool
        deal(WETH_ADDR, ALICE, 1 ether);
        uint256 balancerBefore = IERC20(DAI_ADDR).balanceOf(ALICE);

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(address(permit2Address), type(uint256).max);
        // Encoded solution generated using `test_split_swap_strategy_encoder_simple`
        // but manually replacing the executor address
        // `5c2f5a71f67c01775180adc06909288b4c329308` with the one in this test
        // `5615deb798bb3e4dfa0139dfa1b3d433cc23b72f`
        (bool success,) = tychoRouterAddr.call(
            hex"4860f9ed0000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000006b175474e89094c44da98b954eedeac495271d0f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000067c43ba900000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ede3eca2a72b3aecc820e955b36f38437d0139500000000000000000000000000000000000000000000000000000000679cb5b10000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000000415bfd02ffd61c11192d1b54d76e0af125afbb32568aad37ec35f918bd5fb304cd314954213ed77c0d071301ddc45243ad57e86fe18f2905b682acc4f1a43ad8dc1c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005c005a00010000005615deb798bb3e4dfa0139dfa1b3d433cc23b72fbd0625abc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a478c2975ab1ea89e8196811f51a7b7ade33eb113ede3eca2a72b3aecc820e955b36f38437d013950000000000"
        );

        vm.stopPrank();

        uint256 balancerAfter = IERC20(DAI_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertGt(balancerAfter - balancerBefore, 26173932);
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
        IERC20(WETH_ADDR).approve(address(permit2Address), type(uint256).max);
        // Encoded solution generated using
        // `test_split_swap_strategy_encoder_simple_route_wrap`
        // but manually replacing the executor address
        // `5c2f5a71f67c01775180adc06909288b4c329308` with the one in this test
        // `5615deb798bb3e4dfa0139dfa1b3d433cc23b72f`
        (bool success,) = tychoRouterAddr.call{value: 1 ether}(
            hex"4860f9ed0000000000000000000000000000000000000000000000000de0b6b3a764000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006b175474e89094c44da98b954eedeac495271d0f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000067c9179300000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ede3eca2a72b3aecc820e955b36f38437d013950000000000000000000000000000000000000000000000000000000067a1919b000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000041cea77a63613f6a02aaee522c91f9569b8377a7f0200d141fafa3e1c42011e1c668555b49a1e7dd960091d0e33764ad24db6550bc761e228864495b478f1a23721b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005c005a00020000005615deb798bb3e4dfa0139dfa1b3d433cc23b72fbd0625abc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a478c2975ab1ea89e8196811f51a7b7ade33eb113ede3eca2a72b3aecc820e955b36f38437d013950000000000"
        );

        vm.stopPrank();

        uint256 balancerAfter = IERC20(DAI_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertGt(balancerAfter - balancerBefore, 26173932);
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
        IERC20(DAI_ADDR).approve(address(permit2Address), type(uint256).max);
        // Encoded solution generated using
        // `test_split_swap_strategy_encoder_simple_route_unwrap`
        // but manually replacing the executor address
        // `5c2f5a71f67c01775180adc06909288b4c329308` with the one in this test
        // `5615deb798bb3e4dfa0139dfa1b3d433cc23b72f`
        (bool success,) = tychoRouterAddr.call(
            hex"4860f9ed0000000000000000000000000000000000000000000000a2a15d09519be000000000000000000000000000006b175474e89094c44da98b954eedeac495271d0f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc20000000000000000000000006b175474e89094c44da98b954eedeac495271d0f0000000000000000000000000000000000000000000000a2a15d09519be000000000000000000000000000000000000000000000000000000000000067c9185300000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ede3eca2a72b3aecc820e955b36f38437d013950000000000000000000000000000000000000000000000000000000067a1925b000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000041fd1c3dfce5afcb47988cc68165d5de64186cedbeb7eee6fc9cd087bceeaacdfe1ab799d60e0c628f24edfd9819b94ed60846dd23240c481f1d6e5470a7815a891c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005c005a00010000005615deb798bb3e4dfa0139dfa1b3d433cc23b72fbd0625ab6b175474e89094c44da98b954eedeac495271d0fa478c2975ab1ea89e8196811f51a7b7ade33eb113ede3eca2a72b3aecc820e955b36f38437d013950100000000"
        );

        vm.stopPrank();

        uint256 balancerAfter = ALICE.balance;

        assertTrue(success, "Call Failed");
        assertGt(balancerAfter - balancerBefore, 26173932);
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
        IERC20(WETH_ADDR).approve(address(permit2Address), type(uint256).max);
        // Encoded solution generated using `test_split_swap_strategy_encoder_complex`
        // but manually replacing the executor address
        // `5c2f5a71f67c01775180adc06909288b4c329308` with the one in this test
        // `5615deb798bb3e4dfa0139dfa1b3d433cc23b72f`
        (bool success,) = tychoRouterAddr.call(
            hex"4860f9ed0000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000067c48ea700000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ede3eca2a72b3aecc820e955b36f38437d0139500000000000000000000000000000000000000000000000000000000679d08af00000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000004197c2ff7801fa573e4e8e4af1df41499045485c2b48d090833dc85be38e002c1a1e7ef354285d79c2dcb40c4837e5156069de9aaf42365aef54fdc4cca2c76ccb1b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000170005a00028000005615deb798bb3e4dfa0139dfa1b3d433cc23b72fbd0625abc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a478c2975ab1ea89e8196811f51a7b7ade33eb113ede3eca2a72b3aecc820e955b36f38437d0139500005a00010000005615deb798bb3e4dfa0139dfa1b3d433cc23b72fbd0625abc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2bb2b8038a1640196fbe3e38816f3e67cba72d9403ede3eca2a72b3aecc820e955b36f38437d0139500005a02030000005615deb798bb3e4dfa0139dfa1b3d433cc23b72fbd0625ab6b175474e89094c44da98b954eedeac495271d0fae461ca67b15dc8dc81ce7615e0320da1a9ab8d53ede3eca2a72b3aecc820e955b36f38437d0139501005a01030000005615deb798bb3e4dfa0139dfa1b3d433cc23b72fbd0625ab2260fac5e5542a773aa44fbcfedf7c193bc2c599004375dff511095cc5a197a54140a24efef3a4163ede3eca2a72b3aecc820e955b36f38437d013950100000000000000000000000000000000"
        );

        vm.stopPrank();

        uint256 balancerAfter = IERC20(USDC_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertGe(balancerAfter - balancerBefore, 26173932);

        // All input tokens are transferred to the router at first. Make sure we used
        // all of it (and thus our splits are correct).
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }
}
