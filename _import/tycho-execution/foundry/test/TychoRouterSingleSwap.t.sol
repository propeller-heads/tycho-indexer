pragma solidity ^0.8.26;

import {TychoRouter, ClientFeeParams} from "@src/TychoRouter.sol";
import {Dispatcher__UnsupportedSingleHopCycle} from "@src/Dispatcher.sol";
import "./TychoRouterTestSetup.sol";
import {Vault__InsufficientBalance} from "@src/Vault.sol";

contract LyingSwapOutputPool {
    // Fake UniswapV2 pool that reports reserves that would result in ~1000 USDC output
    // for 1 WETH, but never transfers tokens.
    uint112 private _reserve0;
    uint112 private _reserve1;

    constructor() {
        _reserve0 = 1_000_000e6; // 1M USDC
        _reserve1 = 1000e18; //     1000 WETH
    }

    function getReserves() external view returns (uint112, uint112, uint32) {
        return (_reserve0, _reserve1, uint32(block.timestamp));
    }

    // Does nothing.
    function swap(uint256, uint256, address, bytes calldata) external {}
}

contract FalseTokenCallbackPool is TychoRouterTestSetup {
    // When swap() is called, calls back into TychoRouter with crafted data
    // instructing the router to transfer USDC to this contract.

    function swap(address, bool, int256, uint160, bytes calldata)
        external
        returns (int256, int256)
    {
        bytes memory callbackData = abi.encodeWithSignature(
            "slipstreamsCallback(int256,int256,bytes)",
            int256(1_000_000e6), // amount to steal
            int256(0),
            abi.encodePacked(USDC_ADDR, bytes23(0)) // token to steal
        );
        (bool success,) = address(msg.sender).call(callbackData);
        IERC20(DAI_ADDR).transfer(address(msg.sender), 1000e6);
        require(success, "Callback failed");
        return (0, 0);
    }
}

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

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        tychoRouter.singleSwapPermit2(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            2008817438608734439722,
            ALICE,
            noClientFee(),
            permitSingle,
            signature,
            swap
        );

        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertEq(daiBalance, 2018817438608734439722);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), 0);

        vm.stopPrank();
    }

    function testSingleSwapTransferFrom() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // Checks amount out at the end
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        // Approve the tokenIn to be transferred to the router
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 2000 * 1e18;
        uint256 amountOut = tychoRouter.singleSwap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            ALICE,
            noClientFee(),
            swap
        );

        uint256 expectedAmount = 2018817438608734439722;
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

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        vm.expectRevert(TychoRouter__UndefinedMinAmountOut.selector);
        tychoRouter.singleSwap(
            amountIn, WETH_ADDR, DAI_ADDR, 0, ALICE, noClientFee(), swap
        );
    }

    function testSingleSwapZeroInput() public {
        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);
        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        vm.expectRevert(TychoRouter__ZeroInput.selector);
        tychoRouter.singleSwap(
            0, WETH_ADDR, DAI_ADDR, 1, ALICE, noClientFee(), swap
        );
    }

    function testArbitraryCallbackToken() public {
        // Attacker controls a Slipstream pool that abuses the callback
        // to steal USDC from the router. The original swap had WETH as an input token
        // and USDT as output.
        //
        // Without the fix:
        // 1. singleSwapUsingVault(amountIn=0) with Slipstreams - fake pool
        // 2. Callback manipulates data to transfer USDC to the fake pool
        // 3. Creates negative USDC delta (nonZeroDeltaCount=1)
        //
        // Blocked by two independent checks:
        //   a) amountIn == 0 reverts (TychoRouter__ZeroInput)
        //   b) inputDelta == 0 would otherwise revert when nonZeroDeltaCount == 1

        uint256 stolenAmount = 1_000_000e6;
        deal(USDC_ADDR, tychoRouterAddr, stolenAmount);

        FalseTokenCallbackPool maliciousPool = new FalseTokenCallbackPool();
        // The pool will transfer back DAI while taking an obscene amount of USDC
        deal(DAI_ADDR, address(maliciousPool), 1000e6);

        bytes memory protocolData = abi.encodePacked(
            WETH_ADDR, DAI_ADDR, bytes3(0), address(maliciousPool), uint8(1)
        );
        bytes memory swap =
            encodeSingleSwap(address(slipstreamsExecutor), protocolData);

        vm.expectRevert(TychoRouter__ZeroInput.selector);
        tychoRouter.singleSwapUsingVault(
            0, WETH_ADDR, DAI_ADDR, 1, tychoRouterAddr, noClientFee(), swap
        );

        // No USDC was stolen
        assertEq(IERC20(USDC_ADDR).balanceOf(tychoRouterAddr), stolenAmount);
        assertEq(IERC20(USDC_ADDR).balanceOf(address(maliciousPool)), 0);
    }

    function testSingleSwapInsufficientApproval() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // Checks amount out at the end
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn - 1);

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 2600 * 1e18;
        vm.expectRevert();
        tychoRouter.singleSwap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            ALICE,
            noClientFee(),
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

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 5600 * 1e18;

        vm.expectRevert(
            abi.encodeWithSelector(
                TychoRouter__NegativeSlippage.selector,
                2018817438608734439722, // actual amountOut
                minAmountOut
            )
        );
        tychoRouter.singleSwap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            ALICE,
            noClientFee(),
            swap
        );
    }

    function testSingleSwapClientContribution() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // The minAmountOut is higher than the output amount from the pool
        // The client contribution is sent with the final amount out to the receiver (not optimized last transfer)
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        // Approve the tokenIn to be transferred to the router
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        // The client will contribute to this swap with their own funds
        uint256 maxContribution = 20 * 1e18;
        deal(DAI_ADDR, ALICE, maxContribution);
        IERC20(DAI_ADDR).approve(address(tychoRouterAddr), maxContribution);

        tychoRouter.deposit(DAI_ADDR, maxContribution);

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 2020 * 1e18;
        ClientFeeParams memory feeParams = ClientFeeParams({
            clientFeeBps: 0,
            clientFeeReceiver: ALICE,
            maxClientContribution: maxContribution,
            deadline: block.timestamp + 1 hours,
            clientSignature: new bytes(0)
        });
        feeParams.clientSignature = signClientFee(
            feeParams,
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            ALICE,
            swap,
            tychoRouterAddr,
            ALICE_PK
        );

        uint256 amountOut = tychoRouter.singleSwap(
            amountIn, WETH_ADDR, DAI_ADDR, minAmountOut, ALICE, feeParams, swap
        );

        assertEq(amountOut, minAmountOut);
        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertEq(daiBalance, minAmountOut);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), 0);
        uint256 swapAmount = 2018817438608734439722;
        assertEq(
            tychoRouter.balanceOf(ALICE, uint256(uint160(DAI_ADDR))),
            maxContribution - (minAmountOut - swapAmount)
        );

        vm.stopPrank();
    }

    function testSingleSwapClientContributionNotEnough() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // The minAmountOut is higher than the output amount from the pool
        // and there won't be enough client contribution to cover the difference.
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        // Approve the tokenIn to be transferred to the router
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 2020 * 1e18;
        vm.expectRevert(
            abi.encodeWithSelector(
                TychoRouter__NegativeSlippage.selector,
                2018817438608734439722, // actual amountOut
                minAmountOut
            )
        );

        tychoRouter.singleSwap(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            ALICE,
            noClientFee(),
            swap
        );

        vm.stopPrank();
    }

    function testSingleSwapClientContributionNotEnoughFunds() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // The minAmountOut is higher than the output amount from the pool
        // the client contribution is high enough but there won't be enough funds in the vault
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        // Approve the tokenIn to be transferred to the router
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 2020 * 1e18;
        uint256 swapAmount = 2018817438608734439722;
        vm.expectRevert(
            abi.encodeWithSelector(
                Vault__InsufficientBalance.selector,
                0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2,
                0x6B175474E89094C44Da98b954EedeAC495271d0F,
                minAmountOut - swapAmount,
                0
            )
        );

        ClientFeeParams memory feeParams = makeClientFeeParams(
            0,
            20 * 1e18,
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            ALICE,
            swap,
            tychoRouterAddr,
            ALICE_PK
        );

        tychoRouter.singleSwap(
            amountIn, WETH_ADDR, DAI_ADDR, minAmountOut, ALICE, feeParams, swap
        );

        vm.stopPrank();
    }

    function testSingleSwapClientContributionDirectlyToReceiver() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V2
        // The minAmountOut is higher than the output amount from the pool
        // The client contribution is sent separately to the user (the last transfer is optimized)
        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        // Approve the tokenIn to be transferred to the router
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        // The client will contribute to this swap with their own funds
        uint256 maxContribution = 20 * 1e18;
        deal(DAI_ADDR, ALICE, maxContribution);
        IERC20(DAI_ADDR).approve(address(tychoRouterAddr), maxContribution);

        tychoRouter.deposit(DAI_ADDR, maxContribution);

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 minAmountOut = 2020 * 1e18;
        ClientFeeParams memory feeParams = makeClientFeeParams(
            0,
            maxContribution,
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            minAmountOut,
            ALICE,
            swap,
            tychoRouterAddr,
            ALICE_PK
        );

        uint256 amountOut = tychoRouter.singleSwap(
            amountIn, WETH_ADDR, DAI_ADDR, minAmountOut, ALICE, feeParams, swap
        );

        assertEq(amountOut, minAmountOut);
        uint256 daiBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertEq(daiBalance, minAmountOut);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), 0);
        uint256 swapAmount = 2018817438608734439722;
        assertEq(
            tychoRouter.balanceOf(ALICE, uint256(uint160(DAI_ADDR))),
            maxContribution - (minAmountOut - swapAmount)
        );

        vm.stopPrank();
    }

    function testSingleSwapFeeOnTransferToken() public {
        // Before fix: reverted with TychoRouter__AmountOutNotFullyReceived
        // because the executor returned the calculated amount (not accounting
        // for the transfer fee), but the receiver got less.
        address ZKML_ADDR = address(0xE92344b4eDF545F3209094B192E46600A19E7C2D);
        address ZKML_WETH_UNIV2_POOL =
            0x315Ed60258702F8d159b98dF4C0DBEb1D7D776dF;

        uint256 amountIn = 1 ether;

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(address(tychoRouterAddr), amountIn);

        bytes memory protocolData =
            encodeUniswapV2Swap(ZKML_WETH_UNIV2_POOL, WETH_ADDR, ZKML_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 amountOut = tychoRouter.singleSwap(
            amountIn, WETH_ADDR, ZKML_ADDR, 1, ALICE, noClientFee(), swap
        );

        // Pool transfer to router 18455652180922777663091
        // router actually received 18086539137304322109830

        assertEq(amountOut, 18086539137304322109830);
        assertEq(IERC20(ZKML_ADDR).balanceOf(ALICE), amountOut);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), 0);

        vm.stopPrank();
    }

    function testSingleSwapFeeOnTransferTokenInput() public {
        // Before fix: reverted with "UniswapV2: K" because the executor
        // calculated amountOut based on the full amountIn, but the pool
        // only received amountIn minus the transfer fee.
        address ZKML_ADDR = address(0xE92344b4eDF545F3209094B192E46600A19E7C2D);
        address ZKML_WETH_UNIV2_POOL =
            0x315Ed60258702F8d159b98dF4C0DBEb1D7D776dF;

        uint256 amountIn = 1000 ether;

        deal(ZKML_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        IERC20(ZKML_ADDR).approve(address(tychoRouterAddr), amountIn);

        bytes memory protocolData =
            encodeUniswapV2Swap(ZKML_WETH_UNIV2_POOL, ZKML_ADDR, WETH_ADDR);

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        uint256 amountOut = tychoRouter.singleSwap(
            amountIn, ZKML_ADDR, WETH_ADDR, 1, ALICE, noClientFee(), swap
        );

        assertGt(amountOut, 0);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), amountOut);

        vm.stopPrank();
    }

    function testSingleSwapIntegration() public {
        // Tests swapping WETH -> DAI on a USV2 pool with regular approvals
        deal(WETH_ADDR, ALICE, 1 ether);
        uint256 balanceBefore = IERC20(DAI_ADDR).balanceOf(ALICE);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, type(uint256).max);
        bytes memory callData = loadCallDataFromFile(
            "test_single_swap_strategy_encoder_transfer_from"
        );
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, 2018817438608734439722);
    }

    function testSingleSwapIntegrationPermit2() public {
        // Tests swapping WETH -> DAI on a USV2 pool with permit2
        deal(WETH_ADDR, ALICE, 1 ether);
        uint256 balanceBefore = IERC20(DAI_ADDR).balanceOf(ALICE);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);
        bytes memory callData =
            loadCallDataFromFile("test_single_swap_strategy_encoder");
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, 2018817438608734439722);
    }

    function testLyingSwapOutputPool() public {
        // A fake UniswapV2 pool reports reserves implying ~1000 USDC output for 1
        // WETH, but its swap() never transfers tokens. The Dispatcher's balance-diff
        // correctly measures 0 output, and the slippage check reverts the transaction.

        LyingSwapOutputPool fakePool = new LyingSwapOutputPool();

        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, amountIn);

        bytes memory protocolData =
            encodeUniswapV2Swap(address(fakePool), WETH_ADDR, USDC_ADDR);
        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        // The executor calculates ~996 USDC from fake reserves and calls pool.swap(),
        // but the pool sends nothing.
        vm.expectRevert(
            abi.encodeWithSelector(
                TychoRouter__NegativeSlippage.selector, uint256(0), uint256(1)
            )
        );
        tychoRouter.singleSwap(
            amountIn,
            WETH_ADDR,
            USDC_ADDR,
            1, // min amount
            ALICE,
            noClientFee(),
            swap
        );
        vm.stopPrank();
    }

    function testSingleHopCyclicSwapReverts() public {
        // Any swap where tokenIn == tokenOut within a single executor call is blocked
        // by Dispatcher.__UnsupportedSingleHopCycle.
        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, amountIn);

        bytes memory protocolData =
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, WETH_ADDR);
        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        vm.expectRevert(
            abi.encodeWithSelector(
                Dispatcher__UnsupportedSingleHopCycle.selector, WETH_ADDR
            )
        );
        tychoRouter.singleSwap(
            amountIn, WETH_ADDR, WETH_ADDR, 1, ALICE, noClientFee(), swap
        );
        vm.stopPrank();
    }
}
