// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../TychoRouterTestSetup.sol";
import "@permit2/src/interfaces/IAllowanceTransfer.sol";
import "@src/executors/SlipstreamsExecutor.sol";
import {Constants} from "../Constants.sol";
import {Permit2TestHelper} from "../Permit2TestHelper.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";

contract SlipstreamsExecutorExposed is SlipstreamsExecutor {
    constructor(address _factory, address _permit2)
        SlipstreamsExecutor(_factory, _permit2)
    {}

    function decodeData(bytes calldata data)
        external
        pure
        returns (
            address inToken,
            address outToken,
            int24 tick_spacing,
            RestrictTransferFrom.TransferType transferType,
            address receiver,
            address target,
            bool zeroForOne
        )
    {
        return _decodeData(data);
    }

    function verifyPairAddress(
        address tokenA,
        address tokenB,
        int24 tick_spacing,
        address target
    ) external view {
        _verifyPairAddress(tokenA, tokenB, tick_spacing, target);
    }
}

contract SlipstreamsExecutorTest is
    Test,
    TestUtils,
    Constants,
    Permit2TestHelper
{
    using SafeERC20 for IERC20;

    SlipstreamsExecutorExposed slipstreamsExposed;
    IERC20 DAI = IERC20(DAI_ADDR);
    IAllowanceTransfer permit2;

    function setUp() public {
        uint256 forkBlock = 37987780;
        vm.createSelectFork(vm.rpcUrl("base"), forkBlock);

        slipstreamsExposed = new SlipstreamsExecutorExposed(
            SLIPSTREAMS_FACTORY_BASE, PERMIT2_ADDRESS
        );
        permit2 = IAllowanceTransfer(PERMIT2_ADDRESS);
    }

    function testDecodeParams() public view {
        int24 expectedTickSpacing = 100;
        bytes memory data = abi.encodePacked(
            BASE_WETH,
            BASE_USDC,
            expectedTickSpacing,
            RestrictTransferFrom.TransferType.Transfer,
            address(2),
            address(3),
            false
        );

        (
            address tokenIn,
            address tokenOut,
            int24 tick_spacing,
            RestrictTransferFrom.TransferType transferType,
            address receiver,
            address target,
            bool zeroForOne
        ) = slipstreamsExposed.decodeData(data);

        assertEq(tokenIn, BASE_WETH);
        assertEq(tokenOut, BASE_USDC);
        assertEq(tick_spacing, expectedTickSpacing);
        assertEq(receiver, address(2));
        assertEq(target, address(3));
        assertEq(zeroForOne, false);
        assertEq(
            uint8(transferType),
            uint8(RestrictTransferFrom.TransferType.Transfer)
        );
    }

    function testSwap() public {
        uint256 amountIn = 10 ** 18;
        deal(BASE_WETH, address(slipstreamsExposed), amountIn);

        bool zeroForOne = true;

        bytes memory data = abi.encodePacked(
            BASE_WETH,
            BASE_USDC,
            IUniswapV3Pool(SLIPSTREAMS_WETH_USDC_POOL).tickSpacing(),
            RestrictTransferFrom.TransferType.Transfer,
            address(this),
            SLIPSTREAMS_WETH_USDC_POOL,
            zeroForOne
        );

        uint256 amountOut = slipstreamsExposed.swap(amountIn, data);

        assertEq(IERC20(BASE_WETH).balanceOf(address(slipstreamsExposed)), 0);
        assertGe(IERC20(BASE_USDC).balanceOf(address(this)), amountOut);
    }

    function testDecodeParamsInvalidDataLength() public {
        bytes memory invalidParams =
            abi.encodePacked(BASE_WETH, address(2), address(3));

        vm.expectRevert(SlipstreamsExecutor__InvalidDataLength.selector);
        slipstreamsExposed.decodeData(invalidParams);
    }

    function testVerifyPairAddress() public view {
        slipstreamsExposed.verifyPairAddress(
            BASE_WETH, BASE_USDC, 100, SLIPSTREAMS_WETH_USDC_POOL
        );
    }

    function testSlipstreamsCallback() public {
        uint24 poolTickSpacing = 100;
        uint256 amountOwed = 1000000000000000000;
        deal(BASE_WETH, address(slipstreamsExposed), amountOwed);
        uint256 initialPoolReserve =
            IERC20(BASE_WETH).balanceOf(SLIPSTREAMS_WETH_USDC_POOL);

        vm.startPrank(SLIPSTREAMS_WETH_USDC_POOL);
        bytes memory protocolData = abi.encodePacked(
            BASE_WETH,
            BASE_USDC,
            poolTickSpacing,
            RestrictTransferFrom.TransferType.Transfer,
            address(slipstreamsExposed)
        );
        uint256 dataOffset = 3; // some offset
        uint256 dataLength = protocolData.length;

        bytes memory callbackData = abi.encodePacked(
            bytes4(0xfa461e33),
            int256(amountOwed), // amount0Delta
            int256(0), // amount1Delta
            dataOffset,
            dataLength,
            protocolData
        );
        slipstreamsExposed.handleCallback(callbackData);
        vm.stopPrank();

        uint256 finalPoolReserve =
            IERC20(BASE_WETH).balanceOf(SLIPSTREAMS_WETH_USDC_POOL);
        assertEq(finalPoolReserve - initialPoolReserve, amountOwed);
    }

    function testSwapFailureInvalidTarget() public {
        uint256 amountIn = 10 ** 18;
        deal(BASE_WETH, address(slipstreamsExposed), amountIn);
        bool zeroForOne = false;
        address fakePool = DUMMY; // Contract with minimal code

        bytes memory protocolData = abi.encodePacked(
            BASE_WETH,
            BASE_USDC,
            uint24(100),
            RestrictTransferFrom.TransferType.Transfer,
            address(this),
            fakePool,
            zeroForOne
        );

        vm.expectRevert(SlipstreamsExecutor__InvalidTarget.selector);
        slipstreamsExposed.swap(amountIn, protocolData);
    }

    function encodeSlipstreamsSwap(
        address tokenIn,
        address tokenOut,
        address receiver,
        address target,
        bool zero2one,
        RestrictTransferFrom.TransferType transferType
    ) internal view returns (bytes memory) {
        IUniswapV3Pool pool = IUniswapV3Pool(target);
        return abi.encodePacked(
            tokenIn,
            tokenOut,
            pool.tickSpacing(),
            transferType,
            receiver,
            target,
            zero2one
        );
    }

    function testExportContract() public {
        exportRuntimeBytecode(address(slipstreamsExposed), "Slipstreams");
    }
}

contract TychoRouterForSlipstreamsTest is TychoRouterTestSetup {
    function getChain() public pure override returns (string memory) {
        return "base";
    }

    function getForkBlock() public pure override returns (uint256) {
        return 37987780;
    }

    function testSingleSlipstreamsIntegration() public {
        deal(BASE_WETH, ALICE, 1 ether);
        uint256 balanceBefore = IERC20(BASE_USDC).balanceOf(ALICE);

        vm.startPrank(ALICE);
        IERC20(BASE_WETH).approve(tychoRouterAddr, type(uint256).max);

        bytes memory callData =
            loadCallDataFromFile("test_single_encoding_strategy_slipstreams");
        (bool success,) = tychoRouterAddr.call(callData);

        uint256 balanceAfter = IERC20(BASE_USDC).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertEq(IERC20(BASE_WETH).balanceOf(tychoRouterAddr), 0);
        assertGt(balanceAfter, balanceBefore);
    }

    function testSequentialSlipstreamsIntegration() public {
        deal(BASE_WETH, ALICE, 1 ether);
        uint256 balanceBefore = IERC20(BASE_cbBTC).balanceOf(ALICE);

        vm.startPrank(ALICE);
        IERC20(BASE_WETH).approve(tychoRouterAddr, type(uint256).max);

        bytes memory callData = loadCallDataFromFile(
            "test_sequential_encoding_strategy_slipstreams"
        );
        (bool success,) = tychoRouterAddr.call(callData);

        uint256 balanceAfter = IERC20(BASE_cbBTC).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertEq(IERC20(BASE_WETH).balanceOf(tychoRouterAddr), 0);
        assertGt(balanceAfter, balanceBefore);
    }
}
