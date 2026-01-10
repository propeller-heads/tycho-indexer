// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../TychoRouterTestSetup.sol";
import {FluidV1Executor, IFluidV1Dex} from "@src/executors/FluidV1Executor.sol";
import {Constants} from "../Constants.sol";
import "forge-std/Test.sol";

contract FluidV1ExecutorExposed is FluidV1Executor {
    constructor(address _liquidity, address _permit2)
        FluidV1Executor(_liquidity, _permit2)
    {}

    function decodeData(bytes calldata data)
        external
        pure
        returns (
            IFluidV1Dex dex,
            bool zero2one,
            address receiver,
            TransferType transferType,
            bool isNative
        )
    {
        return _decodeData(data);
    }

    function setSwapParams(IFluidV1Dex dex, TransferType transferType) public {
        _setSwapParams(dex, transferType);
    }

    function getCurrentDex() public view returns (address) {
        return _getCurrentDex();
    }

    function getTransferType() public view returns (TransferType) {
        return _getTransferType();
    }

    function dexCallback(address, uint256) public {
        handleCallback(msg.data);
    }
}

contract FluidV1ExecutorTest is Test, Constants {
    using SafeERC20 for IERC20;

    FluidV1ExecutorExposed executor;

    function setUp() public {
        uint256 forkBlock = 23748828;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        executor =
            new FluidV1ExecutorExposed(FLUIDV1_LIQUIDITY, PERMIT2_ADDRESS);
    }

    function testDecodeData() public view {
        address dex = 0x1DD125C32e4B5086c63CC13B3cA02C4A2a61Fa9b;
        bytes memory params = abi.encodePacked(
            dex,
            true,
            address(this),
            RestrictTransferFrom.TransferType.Transfer,
            false
        );
        IFluidV1Dex dexVal;
        bool zero2oneVal;
        address receiverVal;
        RestrictTransferFrom.TransferType transferTypeVal;
        bool isNative;

        (dexVal, zero2oneVal, receiverVal, transferTypeVal, isNative) =
            executor.decodeData(params);

        assertEq(address(dexVal), dex);
        assert(zero2oneVal);
        assertEq(receiverVal, address(this));
        assertEq(
            uint8(transferTypeVal),
            uint8(RestrictTransferFrom.TransferType.Transfer)
        );
    }

    function testSwapParamsRoundtrip() public {
        address dexAddress = 0x1DD125C32e4B5086c63CC13B3cA02C4A2a61Fa9b;
        IFluidV1Dex dex = IFluidV1Dex(dexAddress);
        RestrictTransferFrom.TransferType transferType =
        RestrictTransferFrom.TransferType.Transfer;

        executor.setSwapParams(dex, transferType);
        address dexVal = executor.getCurrentDex();
        RestrictTransferFrom.TransferType transferTypeVal =
            executor.getTransferType();

        assertEq(dexVal, dexAddress);
        assertEq(
            uint8(transferTypeVal),
            uint8(RestrictTransferFrom.TransferType.Transfer)
        );
    }

    function testVerifyCallbackOk() public {
        address dexAddress = 0x1DD125C32e4B5086c63CC13B3cA02C4A2a61Fa9b;
        executor.setSwapParams(
            IFluidV1Dex(dexAddress), RestrictTransferFrom.TransferType.Transfer
        );
        bytes memory param = abi.encodePacked(bytes4(0x9410ae88));

        vm.prank(dexAddress);
        executor.verifyCallback(param);
    }

    function testVerifyCallbackBadSender() public {
        address dexAddress = 0x1DD125C32e4B5086c63CC13B3cA02C4A2a61Fa9b;
        executor.setSwapParams(
            IFluidV1Dex(dexAddress), RestrictTransferFrom.TransferType.Transfer
        );
        bytes memory param = abi.encodePacked(bytes4(0x9410ae88));

        vm.expectRevert();
        executor.verifyCallback(param);
    }

    function testVerifyCallbackBadSelector() public {
        address dexAddress = 0x1DD125C32e4B5086c63CC13B3cA02C4A2a61Fa9b;
        executor.setSwapParams(
            IFluidV1Dex(dexAddress), RestrictTransferFrom.TransferType.Transfer
        );
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
        bytes memory params = abi.encodePacked(
            dex,
            true,
            address(BOB),
            RestrictTransferFrom.TransferType.Transfer,
            false
        );
        deal(address(sUSDe), address(executor), amountIn);
        uint256 balanceBefore = USDT.balanceOf(BOB);

        uint256 amountOut = executor.swap(amountIn, params);

        uint256 balanceAfter = USDT.balanceOf(BOB);
        assertEq(balanceAfter - balanceBefore, amountOut);
    }

    function testSellNative() public {
        address dex = 0xDD72157A021804141817d46D9852A97addfB9F59;
        IERC20 ezETH = IERC20(0xbf5495Efe5DB9ce00f80364C8B423567e58d2110);
        uint256 amountIn = 10e18;
        bytes memory params = abi.encodePacked(
            dex,
            false,
            address(BOB),
            RestrictTransferFrom.TransferType.Transfer,
            true
        );
        deal(address(executor), amountIn);
        uint256 balanceBefore = ezETH.balanceOf(BOB);

        uint256 amountOut = executor.swap(amountIn, params);

        uint256 balanceAfter = ezETH.balanceOf(BOB);
        assertEq(balanceAfter - balanceBefore, amountOut);
    }

    function testBuyNative() public {
        address dex = 0xDD72157A021804141817d46D9852A97addfB9F59;
        IERC20 ezETH = IERC20(0xbf5495Efe5DB9ce00f80364C8B423567e58d2110);
        uint256 amountIn = 10e18;
        bytes memory params = abi.encodePacked(
            dex,
            true,
            address(BOB),
            RestrictTransferFrom.TransferType.Transfer,
            false
        );
        deal(address(ezETH), address(executor), amountIn);
        uint256 balanceBefore = BOB.balance;

        uint256 amountOut = executor.swap(amountIn, params);

        uint256 balanceAfter = BOB.balance;
        assertEq(balanceAfter - balanceBefore, amountOut);
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
