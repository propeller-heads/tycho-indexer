pragma solidity ^0.8.26;

import {TestUtils} from "../TestUtils.sol";
import {
    AerodromeV1Executor,
    AerodromeV1Executor__InvalidDataLength,
    AerodromeV1Executor__InvalidTokenPair,
    IAerodromeV1Pool
} from "@src/executors/AerodromeV1Executor.sol";
import {Constants} from "../Constants.sol";
import {TransferManager} from "@src/TransferManager.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract AerodromeV1ExecutorExposed is AerodromeV1Executor {
    function decodeParams(bytes calldata data)
        external
        pure
        returns (address target, address tokenIn, address tokenOut)
    {
        return _decodeData(data);
    }
}

contract AerodromeV1ExecutorTest is Constants, TestUtils {
    address constant AERODROME_V1_POOL =
        0x723AEf6543aecE026a15662Be4D3fb3424D502A9;
    address constant AERODROME_V1_TOKEN0 =
        0x236aa50979D5f3De3Bd1Eeb40E81137F22ab794b;
    address constant AERODROME_V1_TOKEN1 =
        0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA;

    AerodromeV1ExecutorExposed aerodromeV1Exposed;
    IERC20 token0 = IERC20(AERODROME_V1_TOKEN0);
    IERC20 token1 = IERC20(AERODROME_V1_TOKEN1);

    function setUp() public {
        uint256 forkBlock = 44682102;
        vm.createSelectFork(vm.rpcUrl("base"), forkBlock);

        aerodromeV1Exposed = new AerodromeV1ExecutorExposed();
    }

    function testDecodeParams() public view {
        bytes memory params = abi.encodePacked(
            AERODROME_V1_POOL, AERODROME_V1_TOKEN0, AERODROME_V1_TOKEN1
        );

        (address target, address tokenIn, address tokenOut) =
            aerodromeV1Exposed.decodeParams(params);

        assertEq(target, AERODROME_V1_POOL);
        assertEq(tokenIn, AERODROME_V1_TOKEN0);
        assertEq(tokenOut, AERODROME_V1_TOKEN1);
    }

    function testDecodeParamsInvalidDataLength() public {
        bytes memory invalidParams =
            abi.encodePacked(AERODROME_V1_POOL, AERODROME_V1_TOKEN0);

        vm.expectRevert(AerodromeV1Executor__InvalidDataLength.selector);
        aerodromeV1Exposed.decodeParams(invalidParams);
    }

    function testGetTransferData() public {
        bytes memory params = abi.encodePacked(
            AERODROME_V1_POOL, AERODROME_V1_TOKEN0, AERODROME_V1_TOKEN1
        );

        (
            TransferManager.TransferType transferType,
            address receiver,
            address tokenIn,
            address tokenOut,
            bool outputToRouter
        ) = aerodromeV1Exposed.getTransferData(params);

        assertEq(
            uint8(transferType), uint8(TransferManager.TransferType.Transfer)
        );
        assertEq(receiver, AERODROME_V1_POOL);
        assertEq(tokenIn, AERODROME_V1_TOKEN0);
        assertEq(tokenOut, AERODROME_V1_TOKEN1);
        assertEq(outputToRouter, false);
    }

    function testFundsExpectedAddress() public view {
        bytes memory params = abi.encodePacked(
            AERODROME_V1_POOL, AERODROME_V1_TOKEN0, AERODROME_V1_TOKEN1
        );
        address receiver = aerodromeV1Exposed.fundsExpectedAddress(params);
        assertEq(receiver, AERODROME_V1_POOL);
    }

    function testSwapZeroForOne() public {
        uint256 amountIn = 0.01 ether;
        uint256 expectedAmountOut = IAerodromeV1Pool(AERODROME_V1_POOL)
            .getAmountOut(amountIn, AERODROME_V1_TOKEN0);
        bytes memory protocolData = abi.encodePacked(
            AERODROME_V1_POOL, AERODROME_V1_TOKEN0, AERODROME_V1_TOKEN1
        );

        deal(AERODROME_V1_TOKEN0, address(aerodromeV1Exposed), amountIn);
        vm.prank(address(aerodromeV1Exposed));
        token0.transfer(AERODROME_V1_POOL, amountIn);

        uint256 balanceBefore = token1.balanceOf(BOB);
        aerodromeV1Exposed.swap(amountIn, protocolData, BOB);
        uint256 balanceAfter = token1.balanceOf(BOB);

        assertEq(balanceAfter - balanceBefore, expectedAmountOut);
        assertEq(token0.balanceOf(address(aerodromeV1Exposed)), 0);
    }

    function testSwapOneForZero() public {
        uint256 amountIn = 10e6;
        uint256 expectedAmountOut = IAerodromeV1Pool(AERODROME_V1_POOL)
            .getAmountOut(amountIn, AERODROME_V1_TOKEN1);
        bytes memory protocolData = abi.encodePacked(
            AERODROME_V1_POOL, AERODROME_V1_TOKEN1, AERODROME_V1_TOKEN0
        );

        deal(AERODROME_V1_TOKEN1, address(aerodromeV1Exposed), amountIn);
        vm.prank(address(aerodromeV1Exposed));
        token1.transfer(AERODROME_V1_POOL, amountIn);

        uint256 balanceBefore = token0.balanceOf(BOB);
        aerodromeV1Exposed.swap(amountIn, protocolData, BOB);
        uint256 balanceAfter = token0.balanceOf(BOB);

        assertEq(balanceAfter - balanceBefore, expectedAmountOut);
        assertEq(token1.balanceOf(address(aerodromeV1Exposed)), 0);
    }

    function testDecodeIntegration() public view {
        bytes memory protocolData =
            loadCallDataFromFile("test_encode_aerodrome_v1");

        (address target, address tokenIn, address tokenOut) =
            aerodromeV1Exposed.decodeParams(protocolData);

        assertEq(target, AERODROME_V1_POOL);
        assertEq(tokenIn, AERODROME_V1_TOKEN0);
        assertEq(tokenOut, AERODROME_V1_TOKEN1);
    }

    function testSwapIntegration() public {
        bytes memory protocolData =
            loadCallDataFromFile("test_encode_aerodrome_v1");
        uint256 amountIn = 0.01 ether;
        uint256 expectedAmountOut = IAerodromeV1Pool(AERODROME_V1_POOL)
            .getAmountOut(amountIn, AERODROME_V1_TOKEN0);

        deal(AERODROME_V1_TOKEN0, address(aerodromeV1Exposed), amountIn);
        vm.prank(address(aerodromeV1Exposed));
        token0.transfer(AERODROME_V1_POOL, amountIn);

        uint256 balanceBefore = token1.balanceOf(BOB);
        aerodromeV1Exposed.swap(amountIn, protocolData, BOB);
        uint256 balanceAfter = token1.balanceOf(BOB);

        assertEq(balanceAfter - balanceBefore, expectedAmountOut);
        assertEq(token0.balanceOf(address(aerodromeV1Exposed)), 0);
    }

    function testSwapRevertOnInvalidPair() public {
        bytes memory protocolData = abi.encodePacked(
            AERODROME_V1_POOL, AERODROME_V1_TOKEN0, address(0x1234)
        );

        vm.expectRevert(AerodromeV1Executor__InvalidTokenPair.selector);
        aerodromeV1Exposed.swap(1 ether, protocolData, address(this));
    }
}
