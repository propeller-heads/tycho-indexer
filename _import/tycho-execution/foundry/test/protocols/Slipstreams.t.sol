pragma solidity ^0.8.26;

import "../TychoRouterTestSetup.sol";
import "@permit2/src/interfaces/IAllowanceTransfer.sol";
import "@src/executors/SlipstreamsExecutor.sol";
import {Constants} from "../Constants.sol";
import {Permit2TestHelper} from "../Permit2TestHelper.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";

contract SlipstreamsExecutorExposed is SlipstreamsExecutor {
    constructor(address _factory1, address _factory2)
        SlipstreamsExecutor(_factory1, _factory2)
    {}

    function decodeData(bytes calldata data)
        external
        pure
        returns (
            address inToken,
            address outToken,
            int24 tick_spacing,
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

    function uniswapV3SwapCallback(
        int256, /* amount0Delta */
        int256, /* amount1Delta */
        bytes calldata /* data */
    )
        external
    {
        // Use delegatecall to preserve msg.sender
        bytes memory callData =
            abi.encodeWithSignature("getCallbackTransferData(bytes)", msg.data);
        (bool success, bytes memory result) =
            address(this).delegatecall(callData);
        require(success, "Delegatecall failed");

        (, address receiver, address tokenIn, uint256 amount) =
            abi.decode(result, (uint8, address, address, uint256));

        IERC20(tokenIn).transfer(receiver, amount);
        handleCallback(msg.data);
    }
}

contract SlipstreamsExecutorTest is Test, TestUtils, Constants {
    using SafeERC20 for IERC20;

    SlipstreamsExecutorExposed slipstreamsExposed;
    IERC20 DAI = IERC20(DAI_ADDR);

    function setUp() public {
        uint256 forkBlock = 38086214;
        vm.createSelectFork(vm.rpcUrl("base"), forkBlock);

        slipstreamsExposed = new SlipstreamsExecutorExposed(
            SLIPSTREAMS_FACTORY_BASE, SLIPSTREAMS_NEW_FACTORY_BASE
        );
    }

    function testDecodeParams() public view {
        int24 expectedTickSpacing = 100;
        bytes memory data = abi.encodePacked(
            BASE_WETH, BASE_USDC, expectedTickSpacing, address(3), false
        );

        (
            address tokenIn,
            address tokenOut,
            int24 tick_spacing,
            address target,
            bool zeroForOne
        ) = slipstreamsExposed.decodeData(data);

        assertEq(tokenIn, BASE_WETH);
        assertEq(tokenOut, BASE_USDC);
        assertEq(tick_spacing, expectedTickSpacing);
        assertEq(target, address(3));
        assertEq(zeroForOne, false);
    }

    function testGetTransferData() public {
        bytes memory params = "";
        (, address receiver, address tokenIn) =
            slipstreamsExposed.getTransferData(params);

        assertEq(receiver, address(0));
        assertEq(tokenIn, address(0));
    }

    function testGetCallbackTransferData() public {
        uint24 poolTickSpacing = 100;
        uint256 amountOwed = 1000000000000000000;

        bytes memory protocolData =
            abi.encodePacked(BASE_WETH, BASE_USDC, poolTickSpacing);
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
        (, address receiver, address tokenIn, uint256 amount) =
            slipstreamsExposed.getCallbackTransferData(callbackData);

        assertEq(receiver, address(this));
        assertEq(tokenIn, BASE_WETH);
        assertEq(amount, amountOwed);
    }

    function testSwap() public {
        uint256 amountIn = 10 ** 18;
        deal(BASE_WETH, address(slipstreamsExposed), amountIn);

        bool zeroForOne = true;

        bytes memory data = abi.encodePacked(
            BASE_WETH,
            BASE_USDC,
            IUniswapV3Pool(SLIPSTREAMS_WETH_USDC_POOL).tickSpacing(),
            SLIPSTREAMS_WETH_USDC_POOL,
            zeroForOne
        );

        (uint256 amountOut, address tokenOut) =
            slipstreamsExposed.swap(amountIn, data, address(this));

        assertEq(IERC20(BASE_WETH).balanceOf(address(slipstreamsExposed)), 0);
        assertGe(IERC20(BASE_USDC).balanceOf(address(this)), amountOut);
        assertEq(tokenOut, BASE_USDC);
    }

    function testSwapNewFactory() public {
        uint256 amountIn = 10 ** 18;
        deal(BASE_WETH, address(slipstreamsExposed), amountIn);

        bool zeroForOne = false;

        bytes memory data = abi.encodePacked(
            BASE_WETH,
            BASE_BMI,
            IUniswapV3Pool(SLIPSTREAMS_WETH_BMI_POOL).tickSpacing(),
            SLIPSTREAMS_WETH_BMI_POOL,
            zeroForOne
        );

        (uint256 amountOut, address tokenOut) =
            slipstreamsExposed.swap(amountIn, data, address(this));

        assertEq(IERC20(BASE_WETH).balanceOf(address(slipstreamsExposed)), 0);
        assertGe(IERC20(BASE_BMI).balanceOf(address(this)), amountOut);
        assertEq(tokenOut, BASE_BMI);
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

        bytes memory protocolData =
            abi.encodePacked(BASE_WETH, BASE_USDC, poolTickSpacing);
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
        // transfer funds into the pool - this is taken cared of by the Dispatcher now
        vm.prank(address(slipstreamsExposed));
        IERC20(BASE_WETH).transfer(SLIPSTREAMS_WETH_USDC_POOL, amountOwed);
        vm.startPrank(SLIPSTREAMS_WETH_USDC_POOL);
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
            BASE_WETH, BASE_USDC, uint24(100), fakePool, zeroForOne
        );

        vm.expectRevert(SlipstreamsExecutor__InvalidTarget.selector);
        slipstreamsExposed.swap(amountIn, protocolData, BOB);
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
