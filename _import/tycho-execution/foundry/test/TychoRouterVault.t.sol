pragma solidity ^0.8.26;

import "@src/executors/UniswapV4Executor.sol";
import {
    TychoRouter,
    ClientFeeParams,
    TychoRouter__NegativeOutputDelta
} from "@src/TychoRouter.sol";
import {
    Vault__UnexpectedInputDelta,
    Vault__UnexpectedNonZeroCount,
    ERC6909
} from "@src/Vault.sol";
import {TransferManager__DifferentTokenIn} from "@src/TransferManager.sol";
import {IExecutor} from "@interfaces/IExecutor.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {IWETH} from "../lib/IWETH.sol";
import {
    IUniswapV2Pair
} from "@uniswap-v2/contracts/interfaces/IUniswapV2Pair.sol";
import "./TychoRouterTestSetup.sol";
import {WethExecutor} from "../src/executors/WethExecutor.sol";

/**
 * @title TychoRouterUsingVaultTest
 * @notice Test cases for different swap scenarios relating to the Vault
 */
contract TychoRouterUsingVaultTest is TychoRouterTestSetup {
    function getForkBlock() public pure override returns (uint256) {
        return 24480104;
    }

    function testCannotDepositWhenPaused() public {
        uint256 depositAmount = 1 ether;
        deal(WETH_ADDR, ALICE, depositAmount * 2);
        vm.prank(PAUSER);
        tychoRouter.pause();

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, depositAmount);
        vm.expectRevert();
        tychoRouter.deposit(WETH_ADDR, depositAmount);
        vm.stopPrank();

        assertEq(tychoRouter.balanceOf(ALICE, uint256(uint160(WETH_ADDR))), 0);
    }

    // ==================== Transfer tests ====================
    function testSplitSwapUsesVaultBalance() public {
        // A correctly encoded split swap uses vault's funds
        //          ->   WBTC (60%)
        // 1 WETH
        //          ->   WBTC (40%)
        //       (univ2)
        bytes[] memory swaps = new bytes[](2);

        // WETH -> WBTC (60%)
        swaps[0] = encodeSplitSwap(
            uint8(0),
            uint8(1),
            (0xffffff * 60) / 100, // 60%
            address(usv2Executor),
            encodeUniswapV2Swap(WETH_WBTC_POOL, WETH_ADDR, WBTC_ADDR)
        );

        // WETH -> WBTC (40%)
        swaps[1] = encodeSplitSwap(
            uint8(0),
            uint8(1),
            0, // 40%
            address(usv2Executor),
            encodeUniswapV2Swap(WETH_WBTC_POOL, WETH_ADDR, WBTC_ADDR)
        );

        uint256 amountIn = 1 ether;
        uint256 existingVaultBalance = 3 ether;
        deal(WETH_ADDR, ALICE, amountIn + existingVaultBalance);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, existingVaultBalance);
        tychoRouter.deposit(WETH_ADDR, existingVaultBalance);

        uint256 amountOut = tychoRouter.splitSwapUsingVault(
            amountIn,
            WETH_ADDR,
            WBTC_ADDR,
            1, // min amount
            4,
            ALICE, // receiver
            noClientFee(),
            pleEncode(swaps)
        );
        vm.stopPrank();

        // 1 ether was used from vault balance. The rest (2 ether) remains.
        assertEq(
            tychoRouter.balanceOf(ALICE, uint256(uint160(WETH_ADDR))), 2 ether
        );
        // Alice received the amount out
        assertEq(IERC20(WBTC_ADDR).balanceOf(ALICE), amountOut);
    }

    function testMsgValueDoesNotMatchAmountIn() public {
        // Alice transfers in 1 ETH (to use in her swap) via msg.value.
        // By accident, she specified 2 ETH as her input amount. This does not match
        // the amount that she sent - revert.
        uint256 amountIn = 1 ether;
        deal(ALICE, amountIn);

        bytes memory swap = new bytes(0); // IRRELEVANT - should fail before this

        vm.startPrank(ALICE);
        vm.expectRevert(
            abi.encodeWithSelector(
                TychoRouter__MsgValueDoesNotMatchAmountIn.selector,
                amountIn - 1,
                amountIn
            )
        );
        tychoRouter.singleSwap{value: amountIn - 1}(
            amountIn,
            address(0), // ETH
            DAI_ADDR,
            1, // min amount
            ALICE, // receiver
            noClientFee(),
            swap
        );
        vm.stopPrank();
    }

    // ==================== Native Transfer tests ====================
    function _rocketpoolEthRethSwap() private view returns (bytes memory swap) {
        swap = encodeSingleSwap(
            address(rocketpoolExecutor),
            abi.encodePacked(
                uint8(1) // isDeposit = true
            )
        );
    }

    function testTransferNativeInExecutorUserSentETH() public {
        // First swap is native ETH transfer (in msg value), user sent ETH
        // ETH -> rETH via Rocketpool deposit
        uint256 amountIn = 1 ether;
        uint256 existingVaultBalance = 2 ether;
        deal(ALICE, amountIn + existingVaultBalance);

        vm.startPrank(ALICE);
        tychoRouter.deposit{value: existingVaultBalance}(
            address(0), existingVaultBalance
        );
        uint256 amountOut = tychoRouter.singleSwap{value: amountIn}(
            amountIn,
            address(0), // ETH
            RETH_ADDR,
            1, // min amount
            ALICE, // receiver
            noClientFee(),
            _rocketpoolEthRethSwap()
        );
        vm.stopPrank();

        // Alice should have received rETH
        assertEq(amountOut, 863321713651918410);
        assertEq(IERC20(RETH_ADDR).balanceOf(ALICE), amountOut);

        // Alice's ETH vault balance should NOT be touched (still has 2 ether)
        assertEq(tychoRouterAddr.balance, existingVaultBalance);
        assertEq(tychoRouter.balanceOf(ALICE, 0), existingVaultBalance);
    }

    function testTransferNativeInExecutorForgotToSendETH() public {
        // Alice wants to swap ETH but forgets to send it via msg.value
        // Even though she has vault balance, the regular method should revert
        // (vault should only be used with explicit vault methods)
        uint256 amountIn = 1 ether;
        uint256 existingVaultBalance = 2 ether;
        deal(ALICE, existingVaultBalance);

        vm.startPrank(ALICE);
        tychoRouter.deposit{value: existingVaultBalance}(
            address(0), existingVaultBalance
        );
        vm.expectRevert(
            abi.encodeWithSelector(Vault__UnexpectedNonZeroCount.selector, 1)
        );
        tychoRouter.singleSwap(
            // No msg.value sent!
            amountIn,
            address(0), // ETH
            RETH_ADDR,
            1, // min amount
            ALICE, // receiver
            noClientFee(),
            _rocketpoolEthRethSwap()
        );
        vm.stopPrank();
    }

    function testUseNativeVaultBalance() public {
        // First swap is native ETH transfer using vault balance

        uint256 amountIn = 1 ether;
        deal(ALICE, amountIn);

        vm.startPrank(ALICE);
        // Deposit ETH to vault
        tychoRouter.deposit{value: amountIn}(address(0), amountIn);

        uint256 amountOut = tychoRouter.singleSwapUsingVault(
            amountIn,
            address(0), // ETH
            RETH_ADDR,
            1, // min amount
            ALICE, // receiver
            noClientFee(),
            _rocketpoolEthRethSwap()
        );
        vm.stopPrank();

        // Alice should have received rETH
        assertGt(IERC20(RETH_ADDR).balanceOf(ALICE), 0);
        assertEq(IERC20(RETH_ADDR).balanceOf(ALICE), amountOut);

        // Vault balance should be zero
        assertEq(tychoRouter.balanceOf(ALICE, 0), 0);
    }

    function testSequentialSwapNativeETHCredit() public {
        // Output of first swap is native ETH. Second swap successfully uses the
        // credit to perform a native ETH input swap without touching vault funds.
        // Sequential swap: USDC --(USV4)--> ETH --(rocket)--> rETH
        bytes[] memory swaps = new bytes[](2);

        // First swap: USDC -> ETH
        bytes memory pool = abi.encodePacked(
            address(0), // intermediary token
            bytes3(uint24(3000)), // fee
            int24(60), // tick spacing
            address(0), // hook
            bytes2(uint16(0)), // hook data length
            bytes("") // hook data
        );

        bytes memory protocolData = abi.encodePacked(
            USDC_ADDR,
            address(0), // ETH_ADDR
            false, // zeroForOne
            pool
        );

        swaps[0] = encodeSingleSwap(address(usv4Executor), protocolData);

        // Second swap: ETH -> rETH (use credit from first swap)
        swaps[1] = _rocketpoolEthRethSwap();

        uint256 amountIn = 1000e6; // 1000 USDC
        uint256 existingVaultETHBalance = 3 ether;

        deal(USDC_ADDR, ALICE, amountIn);
        deal(ALICE, existingVaultETHBalance);

        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(tychoRouterAddr, amountIn);

        tychoRouter.deposit{value: existingVaultETHBalance}(
            address(0), existingVaultETHBalance
        );

        uint256 amountOut = tychoRouter.sequentialSwap(
            amountIn,
            USDC_ADDR,
            RETH_ADDR,
            1, // min amount
            ALICE, // receiver
            noClientFee(),
            pleEncode(swaps)
        );
        vm.stopPrank();

        // Alice should have received rETH from the last swap
        assertGt(amountOut, 0);
        assertEq(IERC20(RETH_ADDR).balanceOf(ALICE), amountOut);

        // Router ETH balance should not have changed
        assertEq(address(tychoRouter).balance, existingVaultETHBalance);
        assertEq(tychoRouter.balanceOf(ALICE, 0), existingVaultETHBalance);
    }

    // ==================== ProtocolWillDebit tests ====================

    function testProtocolWillDebitFromVaultIntegration() public {
        // Integration test for ProtocolWillDebit with Curve where funds are taken from
        // user's vault in the first swap.
        //
        // This test:
        // 1. Deposits DAI to Alice's vault
        // 2. Executes a single swap: DAI (from vault) -> (Curve TriPool) -> USDC
        // 3. Verifies funds were successfully taken from vault and swap executed
        // 4. Uses calldata generated from Rust encoding test

        uint256 amountIn = 1000 ether; // 1000 DAI
        uint256 vaultBalance = 3000 ether; // Alice starts with 3000 DAI in vault

        deal(DAI_ADDR, ALICE, vaultBalance);

        vm.startPrank(ALICE);
        IERC20(DAI_ADDR).approve(tychoRouterAddr, vaultBalance);
        tychoRouter.deposit(DAI_ADDR, vaultBalance);
        bytes memory calldata_ = loadCallDataFromFile(
            "test_single_encoding_strategy_curve_protocol_will_debit_from_vault"
        );

        (bool success,) = address(tychoRouter).call(calldata_);
        require(success, "Swap failed");

        vm.stopPrank();

        assertEq(
            tychoRouter.balanceOf(ALICE, uint256(uint160(DAI_ADDR))),
            vaultBalance - amountIn
        );

        assertEq(IERC20(USDC_ADDR).balanceOf(ALICE), 999812696);
    }

    // ==================== Circular Vault tests ====================

    function testSequentialCyclicSwapAndVaultIntegration() public {
        // USDC -> WETH -> USDC  using two pools and vault's funds
        uint256 amountIn = 100 * 10 ** 6;
        deal(USDC_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(tychoRouterAddr, type(uint256).max);
        tychoRouter.deposit(USDC_ADDR, amountIn);
        bytes memory callData = loadCallDataFromFile(
            "test_sequential_strategy_cyclic_swap_and_vault"
        );
        (bool success,) = tychoRouterAddr.call(callData);

        assertTrue(success, "Call Failed");
        assertEq(IERC20(USDC_ADDR).balanceOf(ALICE), 99641381);

        vm.stopPrank();
    }

    function testNegativeOutputCyclicalSwap() public {
        // Performs a cyclical swap on a pool which transfers the input amount while
        // offering no output in return. The client contribution is 1 ether, so the
        // client makes up for the whole amount. However, since this pool result in
        // a negative delta at the time of computing client fees, an unprofitable
        // arbitrage is detected and the TychoRouter reverts with
        // TychoRouter__NegativeOutputDelta

        uint256 stolenAmount = 1 ether;
        // The client (Alice) will contribute to this swap with their own funds
        uint256 clientContribution = stolenAmount;
        vm.startPrank(ALICE);
        deal(WETH_ADDR, ALICE, clientContribution);
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), stolenAmount);
        tychoRouter.deposit(WETH_ADDR, clientContribution);

        vm.stopPrank();
        vm.startPrank(BOB);
        deal(WETH_ADDR, BOB, stolenAmount);
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), stolenAmount);
        tychoRouter.deposit(WETH_ADDR, stolenAmount);

        FakeCurvePool maliciousPool = new FakeCurvePool();

        bytes memory protocolData = abi.encodePacked(
            WETH_ADDR,
            WETH_ADDR,
            address(maliciousPool),
            uint8(3),
            uint8(1),
            uint8(1)
        );
        bytes memory swap =
            encodeSingleSwap(address(curveExecutor), protocolData);

        ClientFeeParams memory feeParams =
            makeClientFeeParams(0, stolenAmount, tychoRouterAddr, ALICE_PK);

        int256 negativeOutput = -int256(stolenAmount);
        vm.expectRevert(
            abi.encodeWithSelector(
                TychoRouter__NegativeOutputDelta.selector, negativeOutput
            )
        );
        tychoRouter.singleSwapUsingVault(
            stolenAmount,
            WETH_ADDR,
            WETH_ADDR,
            stolenAmount,
            tychoRouterAddr,
            feeParams,
            swap
        );
    }

    function testZeroOutputDeltaClientContribution() public {
        // The pool returns the same amount as it gets, so the output delta is zero.
        // However, Bob has requested twice this amount, so the rest comes from
        // Alice's client contribution.

        uint256 inputAmount = 1 ether;

        // The client (Alice) will contribute to this swap with their own funds
        uint256 clientContribution = inputAmount;
        vm.startPrank(ALICE);
        deal(WETH_ADDR, ALICE, clientContribution);
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), inputAmount);
        tychoRouter.deposit(WETH_ADDR, clientContribution);

        vm.stopPrank();
        vm.startPrank(BOB);
        deal(WETH_ADDR, BOB, inputAmount);
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), inputAmount);
        tychoRouter.deposit(WETH_ADDR, inputAmount);

        OneToOneCurvePool oneToOnePool = new OneToOneCurvePool();

        bytes memory protocolData = abi.encodePacked(
            WETH_ADDR,
            WETH_ADDR,
            address(oneToOnePool),
            uint8(3),
            uint8(1),
            uint8(1)
        );
        bytes memory swap =
            encodeSingleSwap(address(curveExecutor), protocolData);

        ClientFeeParams memory feeParams =
            makeClientFeeParams(0, inputAmount, tychoRouterAddr, ALICE_PK);

        int256 negativeOutput = -int256(inputAmount);
        tychoRouter.singleSwapUsingVault(
            inputAmount,
            WETH_ADDR,
            WETH_ADDR,
            2 * inputAmount,
            tychoRouterAddr,
            feeParams,
            swap
        );
        uint256 aliceBalance =
            tychoRouter.balanceOf(ALICE, uint256(uint160(WETH_ADDR)));
        uint256 bobBalance =
            tychoRouter.balanceOf(BOB, uint256(uint160(WETH_ADDR)));
        assertEq(aliceBalance, 0);
        // Bob should now have his original amount plus Alice's contribution
        assertEq(bobBalance, 2 * inputAmount);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 2 * inputAmount);
    }

    // ==================== Rebalance Vault tests ====================
    function testSingleSwapIntoVault() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2, with the receiver
        // being the TychoRouter
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);
        uint256 vaultBalanceBefore =
            tychoRouter.balanceOf(ALICE, uint256(uint160(DAI_ADDR)));
        uint256 routerBalanceBefore =
            IERC20(DAI_ADDR).balanceOf(tychoRouterAddr);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);
        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 1900 * 1e18;
        uint256 amountOut = tychoRouter.singleSwap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            tychoRouterAddr, // receiver = tychoRouter to rebalance vault
            noClientFee(),
            swap
        );
        vm.stopPrank();

        uint256 expectedAmount = 1988227843622901622874;
        assertEq(amountOut, expectedAmount);

        // Alice received no DAI
        assertEq(IERC20(DAI_ADDR).balanceOf(ALICE), 0);

        // Output tokens have been credited to vault
        uint256 vaultBalanceAfter =
            tychoRouter.balanceOf(ALICE, uint256(uint160(DAI_ADDR)));
        assertEq(vaultBalanceAfter - vaultBalanceBefore, expectedAmount);

        // Router balance reflects vault balance
        uint256 routerBalanceAfter = IERC20(DAI_ADDR).balanceOf(tychoRouterAddr);
        assertEq(routerBalanceAfter - routerBalanceBefore, expectedAmount);
    }

    function testCyclicalSwapIntoVault() public {
        // Simulate a profitable arbitrage: USDC -> WETH (USV3) -> USDC (USV2)
        // We force the price of the USV2 pool by dealing extra USDC into it, making
        // WETH more expensive in USDC terms on that pool.

        uint256 amountIn = 1_000_000_000; // 1000 USDC
        uint256 expectedAmountOut = 1050886787; // 1050.8 USDC

        // Rebalance USV2 pool: add extra USDC so WETH is worth more USDC there
        deal(
            USDC_ADDR,
            USDC_WETH_USV2,
            IERC20(USDC_ADDR).balanceOf(USDC_WETH_USV2) + 500_000 * 1e6
        );
        IUniswapV2Pair(USDC_WETH_USV2).sync();

        deal(USDC_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);

        uint256 vaultBalanceBefore =
            tychoRouter.balanceOf(ALICE, uint256(uint160(USDC_ADDR)));
        uint256 routerBalanceBefore =
            IERC20(USDC_ADDR).balanceOf(tychoRouterAddr);

        IERC20(USDC_ADDR).approve(address(tychoRouterAddr), amountIn);
        tychoRouter.deposit(USDC_ADDR, amountIn);

        // USDC -> WETH on USV3
        bytes memory usdcWethV3Data =
            encodeUniswapV3Swap(USDC_ADDR, WETH_ADDR, USDC_WETH_USV3, true);

        // WETH -> USDC on USV2 (rebalanced - WETH buys more USDC)
        bytes memory wethUsdcV2Data =
            encodeUniswapV2Swap(USDC_WETH_USV2, WETH_ADDR, USDC_ADDR);

        bytes[] memory swaps = new bytes[](2);
        swaps[0] = encodeSequentialSwap(address(usv3Executor), usdcWethV3Data);
        swaps[1] = encodeSequentialSwap(address(usv2Executor), wethUsdcV2Data);

        uint256 amountOut = tychoRouter.sequentialSwapUsingVault(
            amountIn,
            USDC_ADDR,
            USDC_ADDR,
            amountIn, // min amount out
            tychoRouterAddr, // receiver = tychoRouter to rebalance vault
            noClientFee(),
            pleEncode(swaps)
        );
        vm.stopPrank();

        assertEq(amountOut, expectedAmountOut);

        // Alice received no USDC in her wallet
        assertEq(IERC20(USDC_ADDR).balanceOf(ALICE), 0);

        // Output tokens have been credited to vault
        uint256 vaultBalanceAfter =
            tychoRouter.balanceOf(ALICE, uint256(uint160(USDC_ADDR)));
        assertEq(vaultBalanceAfter - vaultBalanceBefore, expectedAmountOut);

        // Router balance reflects vault balance
        uint256 routerBalanceAfter =
            IERC20(USDC_ADDR).balanceOf(tychoRouterAddr);
        assertEq(routerBalanceAfter - routerBalanceBefore, expectedAmountOut);
    }

    function testCyclicalSwapTransferFromIntoVault() public {
        // Cyclic arb using transferFrom (not vault funds) with output going to
        // the router for vault crediting. This tests the case where
        // transferFrom = true AND receiver = address(this).
        uint256 amountIn = 1_000_000_000; // 1000 USDC
        uint256 expectedAmountOut = 1050886787; // 1050.8 USDC

        // Rebalance USV2 pool: add extra USDC so WETH is worth more USDC there
        deal(
            USDC_ADDR,
            USDC_WETH_USV2,
            IERC20(USDC_ADDR).balanceOf(USDC_WETH_USV2) + 500_000 * 1e6
        );
        IUniswapV2Pair(USDC_WETH_USV2).sync();

        deal(USDC_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);

        uint256 vaultBalanceBefore =
            tychoRouter.balanceOf(ALICE, uint256(uint160(USDC_ADDR)));
        uint256 routerBalanceBefore =
            IERC20(USDC_ADDR).balanceOf(tychoRouterAddr);

        IERC20(USDC_ADDR).approve(address(tychoRouterAddr), amountIn);

        // USDC -> WETH on USV3
        bytes memory usdcWethV3Data =
            encodeUniswapV3Swap(USDC_ADDR, WETH_ADDR, USDC_WETH_USV3, true);

        //WETH -> USDC on USV2 (rebalanced - WETH buys more USDC)
        bytes memory wethUsdcV2Data =
            encodeUniswapV2Swap(USDC_WETH_USV2, WETH_ADDR, USDC_ADDR);

        bytes[] memory swaps = new bytes[](2);
        swaps[0] = encodeSequentialSwap(address(usv3Executor), usdcWethV3Data);
        swaps[1] = encodeSequentialSwap(address(usv2Executor), wethUsdcV2Data);

        uint256 amountOut = tychoRouter.sequentialSwap(
            amountIn,
            USDC_ADDR,
            USDC_ADDR,
            amountIn, // min amount out
            tychoRouterAddr, // receiver = tychoRouter to credit vault
            noClientFee(),
            pleEncode(swaps)
        );
        vm.stopPrank();

        assertEq(amountOut, expectedAmountOut);

        // Alice received no USDC in her wallet
        assertEq(IERC20(USDC_ADDR).balanceOf(ALICE), 0);

        // Output tokens have been credited to vault
        uint256 vaultBalanceAfter =
            tychoRouter.balanceOf(ALICE, uint256(uint160(USDC_ADDR)));
        assertEq(vaultBalanceAfter - vaultBalanceBefore, expectedAmountOut);

        // Router balance reflects vault balance
        uint256 routerBalanceAfter =
            IERC20(USDC_ADDR).balanceOf(tychoRouterAddr);
        assertEq(routerBalanceAfter - routerBalanceBefore, expectedAmountOut);
    }

    function testSplitSwapIntoVault() public {
        // Trade 1 WETH for USDC through DAI and WBTC (4 USV2 split swaps),
        // with receiver = TychoRouter to credit output to vault.
        //          ->   WBTC  ->
        // 1 WETH                   USDC
        //          ->   DAI   ->
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);

        uint256 vaultBalanceBefore =
            tychoRouter.balanceOf(ALICE, uint256(uint160(USDC_ADDR)));
        uint256 routerBalanceBefore =
            IERC20(USDC_ADDR).balanceOf(tychoRouterAddr);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, amountIn);

        bytes[] memory swaps = new bytes[](4);
        swaps[0] = encodeSplitSwap(
            uint8(0),
            uint8(1),
            (0xffffff * 60) / 100,
            address(usv2Executor),
            encodeUniswapV2Swap(WETH_WBTC_POOL, WETH_ADDR, WBTC_ADDR)
        );
        swaps[1] = encodeSplitSwap(
            uint8(1),
            uint8(3),
            uint24(0),
            address(usv2Executor),
            encodeUniswapV2Swap(USDC_WBTC_POOL, WBTC_ADDR, USDC_ADDR)
        );
        swaps[2] = encodeSplitSwap(
            uint8(0),
            uint8(2),
            uint24(0),
            address(usv2Executor),
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR)
        );
        swaps[3] = encodeSplitSwap(
            uint8(2),
            uint8(3),
            uint24(0),
            address(usv2Executor),
            encodeUniswapV2Swap(DAI_USDC_POOL, DAI_ADDR, USDC_ADDR)
        );

        uint256 expectedAmountOut = 1950813311;
        uint256 amountOut = tychoRouter.splitSwap(
            amountIn,
            WETH_ADDR,
            USDC_ADDR,
            1000_000000,
            4,
            tychoRouterAddr, // receiver = router
            noClientFee(),
            pleEncode(swaps)
        );
        vm.stopPrank();

        assertEq(amountOut, expectedAmountOut);

        // Alice received no USDC in her wallet
        assertEq(IERC20(USDC_ADDR).balanceOf(ALICE), 0);

        // Output tokens have been credited to vault
        uint256 vaultBalanceAfter =
            tychoRouter.balanceOf(ALICE, uint256(uint160(USDC_ADDR)));
        assertEq(vaultBalanceAfter - vaultBalanceBefore, expectedAmountOut);

        // Router balance reflects vault balance
        uint256 routerBalanceAfter =
            IERC20(USDC_ADDR).balanceOf(tychoRouterAddr);
        assertEq(routerBalanceAfter - routerBalanceBefore, expectedAmountOut);
    }

    function testRebalanceVault() public {
        // Trade 1 WETH for DAI on Uniswap V2 using vault funds and leaving funds in the router (rebalance).
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, amountIn);
        tychoRouter.deposit(WETH_ADDR, amountIn);

        uint256 wethVaultBefore =
            tychoRouter.balanceOf(ALICE, uint256(uint160(WETH_ADDR)));
        uint256 daiVaultBefore =
            tychoRouter.balanceOf(ALICE, uint256(uint160(DAI_ADDR)));
        uint256 routerDaiBefore = IERC20(DAI_ADDR).balanceOf(tychoRouterAddr);

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);
        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 expectedAmountOut = 1988227843622901622874;
        uint256 amountOut = tychoRouter.singleSwapUsingVault(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            1900 * 1e18,
            tychoRouterAddr, // receiver = router
            noClientFee(),
            swap
        );
        vm.stopPrank();

        assertEq(amountOut, expectedAmountOut);

        // WETH vault was debited
        assertEq(
            tychoRouter.balanceOf(ALICE, uint256(uint160(WETH_ADDR))),
            wethVaultBefore - amountIn
        );

        // Alice received no DAI in her wallet
        assertEq(IERC20(DAI_ADDR).balanceOf(ALICE), 0);

        // DAI was credited to Alice's vault
        uint256 daiVaultAfter =
            tychoRouter.balanceOf(ALICE, uint256(uint160(DAI_ADDR)));
        assertEq(daiVaultAfter - daiVaultBefore, expectedAmountOut);

        // Router balance reflects vault balance
        uint256 routerDaiAfter = IERC20(DAI_ADDR).balanceOf(tychoRouterAddr);
        assertEq(routerDaiAfter - routerDaiBefore, expectedAmountOut);
    }

    function testCyclicVaultDrainIsBlocked() public {
        // Attacker calls singleSwapUsingVault with tokenIn == tokenOut and a
        // fake pool that does nothing. The dispatcher should correctly report a
        // 0 swap output and the router should fail with NegativeSlippage.
        uint256 victimDeposit = 1000e6;
        uint256 stealAmount = 500e6;

        deal(USDC_ADDR, BOB, victimDeposit);
        vm.startPrank(BOB);
        IERC20(USDC_ADDR).approve(tychoRouterAddr, victimDeposit);
        tychoRouter.deposit(USDC_ADDR, victimDeposit);
        vm.stopPrank();

        FakeSlipstreamPool fakePool = new FakeSlipstreamPool();

        bytes memory protocolData = abi.encodePacked(
            USDC_ADDR, USDC_ADDR, bytes3(0), address(fakePool), uint8(1)
        );
        bytes memory swapData =
            encodeSingleSwap(address(slipstreamsExecutor), protocolData);

        vm.prank(ALICE);
        vm.expectRevert(
            abi.encodeWithSelector(
                TychoRouter__NegativeSlippage.selector, 0, stealAmount
            )
        );
        tychoRouter.singleSwapUsingVault(
            stealAmount,
            USDC_ADDR,
            USDC_ADDR,
            stealAmount,
            tychoRouterAddr,
            noClientFee(),
            swapData
        );
    }
}
