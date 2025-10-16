// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../TychoRouterTestSetup.sol";
import {
    BalancerV3Executor__InvalidDataLength
} from "../../src/executors/BalancerV3Executor.sol";

contract BalancerV3ExecutorExposed is BalancerV3Executor {
    constructor(address _permit2) BalancerV3Executor(_permit2) {}

    function decodeParams(bytes calldata data)
        external
        pure
        returns (
            uint256 amountGiven,
            IERC20 tokenIn,
            IERC20 tokenOut,
            address poolId,
            TransferType transferType,
            address receiver
        )
    {
        return _decodeData(data);
    }
}

contract BalancerV3ExecutorTest is Constants, TestUtils {
    using SafeERC20 for IERC20;

    BalancerV3ExecutorExposed balancerV3Exposed;
    address WETH_osETH_pool =
        address(0x57c23c58B1D8C3292c15BEcF07c62C5c52457A42);
    address osETH_ADDR = address(0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38);
    address waEthWETH_ADDR =
        address(0x0bfc9d54Fc184518A81162F8fB99c2eACa081202);

    function setUp() public {
        uint256 forkBlock = 22625131;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        balancerV3Exposed = new BalancerV3ExecutorExposed(PERMIT2_ADDRESS);
    }

    function testDecodeParams() public view {
        bytes memory params = abi.encodePacked(
            uint256(1 ether),
            osETH_ADDR,
            waEthWETH_ADDR,
            WETH_osETH_pool,
            RestrictTransferFrom.TransferType.None,
            BOB
        );

        (
            uint256 amountGiven,
            IERC20 tokenIn,
            IERC20 tokenOut,
            address poolId,
            RestrictTransferFrom.TransferType transferType,
            address receiver
        ) = balancerV3Exposed.decodeParams(params);

        assertEq(amountGiven, 1 ether);
        assertEq(address(tokenIn), osETH_ADDR);
        assertEq(address(tokenOut), waEthWETH_ADDR);
        assertEq(poolId, WETH_osETH_pool);
        assertEq(
            uint8(transferType), uint8(RestrictTransferFrom.TransferType.None)
        );
        assertEq(receiver, BOB);
    }

    function testSwapInvalidDataLength() public {
        bytes memory invalidParams = abi.encodePacked(
            osETH_ADDR,
            waEthWETH_ADDR,
            WETH_osETH_pool,
            RestrictTransferFrom.TransferType.None
        );

        vm.expectRevert(BalancerV3Executor__InvalidDataLength.selector);
        balancerV3Exposed.swap(1 ether, invalidParams);
    }

    function testSwap() public {
        uint256 amountIn = 10 ** 18;
        bytes memory protocolData = abi.encodePacked(
            osETH_ADDR,
            waEthWETH_ADDR,
            WETH_osETH_pool,
            RestrictTransferFrom.TransferType.Transfer,
            BOB
        );

        deal(osETH_ADDR, address(balancerV3Exposed), amountIn);

        uint256 balanceBefore = IERC20(waEthWETH_ADDR).balanceOf(BOB);

        uint256 amountOut = balancerV3Exposed.swap(amountIn, protocolData);

        uint256 balanceAfter = IERC20(waEthWETH_ADDR).balanceOf(BOB);
        assertGt(balanceAfter, balanceBefore);
        assertEq(balanceAfter - balanceBefore, amountOut);
    }

    function testSwapIntegration() public {
        bytes memory protocolData =
            loadCallDataFromFile("test_encode_balancer_v3");

        uint256 amountIn = 10 ** 18;
        address waEthUSDT_ADDR =
            address(0x7Bc3485026Ac48b6cf9BaF0A377477Fff5703Af8);
        address aaveGHO_ADDR =
            address(0xC71Ea051a5F82c67ADcF634c36FFE6334793D24C);
        deal(waEthUSDT_ADDR, address(balancerV3Exposed), amountIn);
        uint256 balanceBefore = IERC20(aaveGHO_ADDR).balanceOf(BOB);

        uint256 amountOut = balancerV3Exposed.swap(amountIn, protocolData);

        uint256 balanceAfter = IERC20(aaveGHO_ADDR).balanceOf(BOB);
        assertGt(balanceAfter, balanceBefore);
        assertEq(balanceAfter - balanceBefore, amountOut);
    }

    function testExportContract() public {
        exportRuntimeBytecode(address(balancerV3Exposed), "BalancerV3");
    }
}

contract TychoRouterForBalancerV3Test is TychoRouterTestSetup {
    function getForkBlock() public pure override returns (uint256) {
        return 22644371;
    }

    function testSingleBalancerV3Integration() public {
        address steakUSDTlite =
            address(0x097FFEDb80d4b2Ca6105a07a4D90eB739C45A666);
        address steakUSDR = address(0x30881Baa943777f92DC934d53D3bFdF33382cab3);
        deal(steakUSDTlite, ALICE, 1 ether);
        uint256 balanceBefore = IERC20(steakUSDTlite).balanceOf(ALICE);

        vm.startPrank(ALICE);
        IERC20(steakUSDTlite).approve(tychoRouterAddr, type(uint256).max);

        bytes memory callData =
            loadCallDataFromFile("test_single_encoding_strategy_balancer_v3");
        (bool success,) = tychoRouterAddr.call(callData);

        uint256 balanceAfter = IERC20(steakUSDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertGe(balanceAfter - balanceBefore, 999725);
        assertEq(IERC20(steakUSDR).balanceOf(tychoRouterAddr), 0);
    }

    function testUSV3BalancerV3Integration() public {
        // It tests if we can optimize the in transfer to balancer v3 (we can not)
        //    WETH ───(USV3)──> WBTC ───(balancer v3)──> QNT
        address QNT_ADDR = address(0x4a220E6096B25EADb88358cb44068A3248254675);
        deal(WETH_ADDR, ALICE, 0.01 ether);
        uint256 balanceBefore = IERC20(QNT_ADDR).balanceOf(ALICE);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, type(uint256).max);
        bytes memory callData =
            loadCallDataFromFile("test_uniswap_v3_balancer_v3");
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = IERC20(QNT_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, 219116541871727003);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }
}
