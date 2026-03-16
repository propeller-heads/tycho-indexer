pragma solidity ^0.8.26;

import "../TychoRouterTestSetup.sol";
import {FluidV1Executor, IFluidV1Dex} from "@src/executors/FluidV1Executor.sol";
import {Constants} from "../Constants.sol";
import "forge-std/Test.sol";

/// Fake pool that lies about its output amount but sends nothing.
contract FakeFluidPool {
    uint256 public immutable bogusAmount;

    constructor(uint256 bogusAmount_) {
        bogusAmount = bogusAmount_;
    }

    function swapInWithCallback(bool, uint256, uint256, address)
        external
        pure
        returns (uint256)
    {
        // No tokens are transferred, but we claim a large output.
        return 1000e6;
    }
}

contract FluidV1ExecutorExposed is FluidV1Executor {
    constructor(address _liquidity) FluidV1Executor(_liquidity) {}

    function decodeData(bytes calldata data)
        external
        pure
        returns (
            IFluidV1Dex dex,
            bool zero2one,
            address outputToken,
            bool isNative
        )
    {
        return _decodeData(data);
    }

    function setCurrentDex(IFluidV1Dex dex) public {
        _setCurrentDex(dex);
    }

    function getCurrentDex() public view returns (address) {
        return _getCurrentDex();
    }

    function dexCallback(address, uint256) public {
        (
            TransferManager.TransferType transferType,
            address receiver,
            address tokenIn,
            uint256 amount
        ) = this.getCallbackTransferData(msg.data);
        if (transferType == TransferManager.TransferType.Transfer) {
            IERC20(tokenIn).transfer(receiver, amount);
        }
        handleCallback(msg.data);
    }
}

contract FluidV1ExecutorTest is Test, Constants {
    FluidV1ExecutorExposed executor;

    function setUp() public {
        uint256 forkBlock = 23748828;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        executor = new FluidV1ExecutorExposed(FLUIDV1_LIQUIDITY);
    }

    function testDecodeData() public view {
        address dex = 0x1DD125C32e4B5086c63CC13B3cA02C4A2a61Fa9b;
        address outputToken = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
        bytes memory params = abi.encodePacked(dex, true, outputToken, false);
        IFluidV1Dex dexVal;
        bool zero2oneVal;
        address outputTokenVal;
        bool isNative;

        (dexVal, zero2oneVal, outputTokenVal, isNative) =
            executor.decodeData(params);

        assertEq(address(dexVal), dex);
        assert(zero2oneVal);
        assertEq(outputTokenVal, outputToken);
    }

    function testGetTransferData() public {
        bytes memory params = "";

        (, address receiver, address tokenIn,,) =
            executor.getTransferData(params);

        assertEq(tokenIn, address(0));
        assertEq(receiver, address(0));
    }

    function testGetCallbackTransferData() public {
        uint256 amountOwed = 1000000000000000000;
        bytes memory data =
            abi.encodeWithSelector(hex"12345678", DAI_ADDR, amountOwed);
        address dexAddress = 0x1DD125C32e4B5086c63CC13B3cA02C4A2a61Fa9b;
        executor.setCurrentDex(IFluidV1Dex(dexAddress));

        (, address receiver, address tokenIn, uint256 amount) =
            executor.getCallbackTransferData(data);

        assertEq(receiver, FLUIDV1_LIQUIDITY);
        assertEq(tokenIn, DAI_ADDR);
        assertEq(amount, amountOwed);
    }

    function testGetCallbackTransferDataETH() public {
        uint256 amountOwed = 1000000000000000000;
        bytes memory data =
            abi.encodeWithSelector(hex"12345678", address(0), amountOwed);
        address dexAddress = 0x1DD125C32e4B5086c63CC13B3cA02C4A2a61Fa9b;
        executor.setCurrentDex(IFluidV1Dex(dexAddress));

        (, address receiver, address tokenIn, uint256 amount) =
            executor.getCallbackTransferData(data);

        assertEq(receiver, FLUIDV1_LIQUIDITY);
        assertEq(tokenIn, address(0));
        assertEq(amount, amountOwed);
    }

    function testSwapParamsRoundtrip() public {
        address dexAddress = 0x1DD125C32e4B5086c63CC13B3cA02C4A2a61Fa9b;
        IFluidV1Dex dex = IFluidV1Dex(dexAddress);

        executor.setCurrentDex(dex);
        address dexVal = executor.getCurrentDex();

        assertEq(dexVal, dexAddress);
    }

    function testVerifyCallbackOk() public {
        address dexAddress = 0x1DD125C32e4B5086c63CC13B3cA02C4A2a61Fa9b;
        executor.setCurrentDex(IFluidV1Dex(dexAddress));
        bytes memory param = abi.encodePacked(bytes4(0x9410ae88));

        vm.prank(dexAddress);
        executor.verifyCallback(param);
    }

    function testVerifyCallbackBadSender() public {
        address dexAddress = 0x1DD125C32e4B5086c63CC13B3cA02C4A2a61Fa9b;
        executor.setCurrentDex(IFluidV1Dex(dexAddress));
        bytes memory param = abi.encodePacked(bytes4(0x9410ae88));

        vm.expectRevert();
        executor.verifyCallback(param);
    }

    function testVerifyCallbackBadSelector() public {
        address dexAddress = 0x1DD125C32e4B5086c63CC13B3cA02C4A2a61Fa9b;
        executor.setCurrentDex(IFluidV1Dex(dexAddress));
        bytes memory param = abi.encodePacked(bytes4(0x00000000));

        vm.prank(dexAddress);
        vm.expectRevert();
        executor.verifyCallback(param);
    }

    function testSwap() public {
        address dex = 0x1DD125C32e4B5086c63CC13B3cA02C4A2a61Fa9b;
        IERC20 sUSDe = IERC20(0x9D39A5DE30e57443BfF2A8307A4256c8797A3497);
        IERC20 USDT = IERC20(0xdAC17F958D2ee523a2206206994597C13D831ec7);
        uint256 amountIn = 10e18;
        bytes memory params = abi.encodePacked(dex, true, address(USDT), false);
        deal(address(sUSDe), address(executor), amountIn);
        uint256 balanceBefore = USDT.balanceOf(BOB);

        (uint256 amountOut, address tokenOut) =
            executor.swap(amountIn, params, BOB);

        uint256 balanceAfter = USDT.balanceOf(BOB);
        assertEq(balanceAfter - balanceBefore, amountOut);
        assertEq(tokenOut, USDT_ADDR);
    }

    function testSellNative() public {
        address dex = 0xDD72157A021804141817d46D9852A97addfB9F59;
        IERC20 ezETH = IERC20(0xbf5495Efe5DB9ce00f80364C8B423567e58d2110);
        uint256 amountIn = 10e18;
        bytes memory params = abi.encodePacked(dex, false, address(ezETH), true);
        deal(address(executor), amountIn);
        uint256 balanceBefore = ezETH.balanceOf(BOB);

        (uint256 amountOut, address tokenOut) =
            executor.swap(amountIn, params, BOB);

        uint256 balanceAfter = ezETH.balanceOf(BOB);
        assertEq(balanceAfter - balanceBefore, amountOut);
        assertEq(tokenOut, address(ezETH));
    }

    function testSwapFakePool() public {
        address tokenOut = USDT_ADDR;
        FakeFluidPool fakePool = new FakeFluidPool(1000e6);
        bytes memory params =
            abi.encodePacked(address(fakePool), true, tokenOut, false);

        (uint256 amountOut,) = executor.swap(1e18, params, BOB);

        assertEq(amountOut, 0, "fake pool should produce zero output");
    }

    function testBuyNative() public {
        address dex = 0xDD72157A021804141817d46D9852A97addfB9F59;
        IERC20 ezETH = IERC20(0xbf5495Efe5DB9ce00f80364C8B423567e58d2110);
        uint256 amountIn = 10e18;
        bytes memory params = abi.encodePacked(dex, true, address(0), false);
        deal(address(ezETH), address(executor), amountIn);
        uint256 balanceBefore = BOB.balance;

        (uint256 amountOut, address tokenOut) =
            executor.swap(amountIn, params, BOB);

        uint256 balanceAfter = BOB.balance;
        assertEq(balanceAfter - balanceBefore, amountOut);
        assertEq(tokenOut, address(0));
    }
}

contract TychoRouterForFluidV1Test is TychoRouterTestSetup {
    function getForkBlock() public pure override returns (uint256) {
        return 23768324;
    }

    function testSingleSwap() public {
        IERC20 sUSDe = IERC20(0x9D39A5DE30e57443BfF2A8307A4256c8797A3497);
        IERC20 USDT = IERC20(0xdAC17F958D2ee523a2206206994597C13D831ec7);
        uint256 amountIn = 10e18;
        deal(address(sUSDe), ALICE, amountIn);
        uint256 balanceBefore = USDT.balanceOf(ALICE);
        vm.startPrank(ALICE);
        sUSDe.approve(tychoRouterAddr, type(uint256).max);
        bytes memory callData =
            loadCallDataFromFile("test_single_encoding_strategy_fluid_v1");

        (bool success,) = tychoRouterAddr.call(callData);

        uint256 balanceAfter = USDT.balanceOf(ALICE);
        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, 1201540);
        assertEq(sUSDe.balanceOf(tychoRouterAddr), 0);
        assertEq(USDT.balanceOf(tychoRouterAddr), 0);
    }

    function testSequentialSwap() public {
        IERC20 sUSDe = IERC20(0x9D39A5DE30e57443BfF2A8307A4256c8797A3497);
        IERC20 USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
        uint256 amountIn = 10e18;
        deal(address(sUSDe), ALICE, amountIn);
        uint256 balanceBefore = USDC.balanceOf(ALICE);
        vm.startPrank(ALICE);
        sUSDe.approve(tychoRouterAddr, type(uint256).max);
        bytes memory callData =
            loadCallDataFromFile("test_sequential_encoding_strategy_fluid_v1");

        (bool success,) = tychoRouterAddr.call(callData);

        uint256 balanceAfter = USDC.balanceOf(ALICE);
        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, 1201417);
        assertEq(sUSDe.balanceOf(tychoRouterAddr), 0);
        assertEq(USDC.balanceOf(tychoRouterAddr), 0);
    }
}
