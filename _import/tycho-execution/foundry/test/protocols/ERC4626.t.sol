// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../TestUtils.sol";
import "../TychoRouterTestSetup.sol";
import "@src/executors/ERC4626Executor.sol";
import {Constants} from "../Constants.sol";

contract ERC4626ExecutorExposed is ERC4626Executor {
    constructor(address _permit2) ERC4626Executor(_permit2) {}

    function decodeParams(bytes calldata data)
        external
        pure
        returns (
            IERC20 inToken,
            address target,
            address receiver,
            RestrictTransferFrom.TransferType transferType
        )
    {
        return _decodeData(data);
    }
}

contract ERC4626ExecutorTest is Constants, TestUtils {
    using SafeERC20 for IERC20;

    ERC4626ExecutorExposed ERC4626Exposed;
    IERC20 WETH = IERC20(WETH_ADDR);
    IERC4626 spETH = IERC4626(0xfE6eb3b609a7C8352A241f7F3A21CEA4e9209B8f);

    function setUp() public {
        uint256 forkBlock = 23922291;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        ERC4626Exposed = new ERC4626ExecutorExposed(PERMIT2_ADDRESS);
    }

    function testDecodeParams() public view {
        bytes memory params = abi.encodePacked(
            WETH_ADDR,
            address(spETH),
            address(2),
            RestrictTransferFrom.TransferType.None
        );

        (
            IERC20 inToken,
            address target,
            address receiver,
            RestrictTransferFrom.TransferType transferType
        ) = ERC4626Exposed.decodeParams(params);

        assertEq(address(inToken), WETH_ADDR);
        assertEq(address(target), address(spETH));
        assertEq(receiver, address(2));
        assertEq(
            uint8(transferType), uint8(RestrictTransferFrom.TransferType.None)
        );
    }

    function testDecodeParamsInvalidDataLength() public {
        bytes memory invalidParams =
            abi.encodePacked(WETH_ADDR, address(spETH), address(2));

        vm.expectRevert(ERC4626Executor__InvalidDataLength.selector);
        ERC4626Exposed.decodeParams(invalidParams);
    }

    function testDeposit() public {
        uint256 amountIn = 10 ** 18;
        bytes memory protocolData = abi.encodePacked(
            WETH_ADDR,
            address(spETH),
            BOB,
            RestrictTransferFrom.TransferType.None
        );

        deal(WETH_ADDR, address(ERC4626Exposed), amountIn);

        uint256 balanceBefore = spETH.balanceOf(BOB);

        uint256 amountOut = ERC4626Exposed.swap(amountIn, protocolData);

        uint256 balanceAfter = spETH.balanceOf(BOB);
        assertGt(balanceAfter, balanceBefore);
        assertEq(balanceAfter - balanceBefore, amountOut);
    }

    function testRedeem() public {
        uint256 amountIn = 10 ** 18;
        bytes memory protocolData = abi.encodePacked(
            address(spETH),
            address(spETH),
            BOB,
            RestrictTransferFrom.TransferType.None
        );

        deal(address(spETH), address(ERC4626Exposed), amountIn);

        uint256 balanceBefore = WETH.balanceOf(BOB);

        uint256 amountOut = ERC4626Exposed.swap(amountIn, protocolData);

        uint256 balanceAfter = WETH.balanceOf(BOB);
        assertGt(balanceAfter, balanceBefore);
        assertEq(balanceAfter - balanceBefore, amountOut);
    }

    function testSwapDepositIntegration() public {
        bytes memory protocolData =
            loadCallDataFromFile("test_encode_erc4626_deposit");

        uint256 amountIn = 10 ** 18;
        deal(GHO_ADDR, address(maverickV2Exposed), amountIn);
        uint256 balanceBefore = USDC.balanceOf(BOB);

        uint256 amountOut = maverickV2Exposed.swap(amountIn, protocolData);

        uint256 balanceAfter = USDC.balanceOf(BOB);
        assertGt(balanceAfter, balanceBefore);
        assertEq(balanceAfter - balanceBefore, amountOut);
    }

    function testSwapRedeemIntegration() public {
        bytes memory protocolData =
            loadCallDataFromFile("test_encode_erc4626_redeem");

        uint256 amountIn = 10 ** 18;
        deal(GHO_ADDR, address(maverickV2Exposed), amountIn);
        uint256 balanceBefore = USDC.balanceOf(BOB);

        uint256 amountOut = maverickV2Exposed.swap(amountIn, protocolData);

        uint256 balanceAfter = USDC.balanceOf(BOB);
        assertGt(balanceAfter, balanceBefore);
        assertEq(balanceAfter - balanceBefore, amountOut);
    }

    function testExportContract() public {
        exportRuntimeBytecode(address(ERC4626Exposed), "ERC4626");
    }
}

contract TychoRouterForERC4626Test is TychoRouterTestSetup {
    function getForkBlock() public pure override returns (uint256) {
        return 23922291;
    }

    function testSingleERC4626Integration() public {
        // deal(BASE_WETH, ALICE, 1 ether);
        // uint256 balanceBefore = IERC20(BASE_USDC).balanceOf(ALICE);

        // vm.startPrank(ALICE);
        // IERC20(BASE_WETH).approve(tychoRouterAddr, type(uint256).max);

        // bytes memory callData =
        //     loadCallDataFromFile("test_single_encoding_strategy_slipstreams");
        // (bool success,) = tychoRouterAddr.call(callData);

        // uint256 balanceAfter = IERC20(BASE_USDC).balanceOf(ALICE);

        // assertTrue(success, "Call Failed");
        // assertEq(IERC20(BASE_WETH).balanceOf(tychoRouterAddr), 0);
        // assertGt(balanceAfter, balanceBefore);
    }

    function testSequentialERC4626Integration() public {
        // deal(BASE_WETH, ALICE, 1 ether);
        // uint256 balanceBefore = IERC20(BASE_cbBTC).balanceOf(ALICE);

        // vm.startPrank(ALICE);
        // IERC20(BASE_WETH).approve(tychoRouterAddr, type(uint256).max);

        // bytes memory callData = loadCallDataFromFile(
        //     "test_sequential_encoding_strategy_slipstreams"
        // );
        // (bool success,) = tychoRouterAddr.call(callData);

        // uint256 balanceAfter = IERC20(BASE_cbBTC).balanceOf(ALICE);

        // assertTrue(success, "Call Failed");
        // assertEq(IERC20(BASE_WETH).balanceOf(tychoRouterAddr), 0);
        // assertGt(balanceAfter, balanceBefore);
    }
}
