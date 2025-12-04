// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../TestUtils.sol";
import "@src/executors/LidoExecutor.sol";
import {Constants} from "../Constants.sol";
import {Permit2TestHelper} from "../Permit2TestHelper.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";

contract LidoExecutorExposed is LidoExecutor {
    constructor(
        address _st_eth_address,
        address _wst_eth_address,
        address _permit2
    ) LidoExecutor(_st_eth_address, _wst_eth_address, _permit2) {}

    function decodeParams(
        bytes calldata data
    )
        external
        pure
        returns (
            address receiver,
            TransferType transferType,
            bool pool,
            bool direction
        )
    {
        return _decodeData(data);
    }
}

contract LidoExecutorTest is Constants, Permit2TestHelper, TestUtils {
    using SafeERC20 for IERC20;

    LidoExecutorExposed LidoExposed;

    function setUp() public {
        uint256 forkBlock = 23934489; //change for a newer block
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        LidoExposed = new LidoExecutorExposed(
            STETH_ADDR,
            WSTETH_ADDR,
            PERMIT2_ADDRESS
        );
    }

    // function testDecodeParams() public view {
    //     bytes memory params = abi.encodePacked(
    //         WETH_ADDR,
    //         address(2),
    //         address(3),
    //         false,
    //         RestrictTransferFrom.TransferType.Transfer
    //     );

    //     (
    //         IERC20 tokenIn,
    //         address target,
    //         address receiver,
    //         bool zeroForOne,
    //         RestrictTransferFrom.TransferType transferType
    //     ) = uniswapV2Exposed.decodeParams(params);

    //     assertEq(address(tokenIn), WETH_ADDR);
    //     assertEq(target, address(2));
    //     assertEq(receiver, address(3));
    //     assertEq(zeroForOne, false);
    //     assertEq(
    //         uint8(transferType),
    //         uint8(RestrictTransferFrom.TransferType.Transfer)
    //     );
    // }

    // function testDecodeParamsInvalidDataLength() public {
    //     bytes memory invalidParams = abi.encodePacked(
    //         WETH_ADDR,
    //         address(2),
    //         address(3)
    //     );

    //     vm.expectRevert(UniswapV2Executor__InvalidDataLength.selector);
    //     uniswapV2Exposed.decodeParams(invalidParams);
    // }

    // function testWrapping() public {
    //     uint256 amountIn = 1 ether;

    //     bytes memory protocolData = abi.encodePacked(
    //         BOB,
    //         RestrictTransferFrom.TransferType.None,
    //         false,
    //         true
    //     );

    //     deal(STETH_ADDR, address(LidoExposed), amountIn);
    //     LidoExposed.swap(amountIn, protocolData);

    //     uint256 finalBalance = IERC20(WSTETH_ADDR).balanceOf(BOB);
    //     assertGe(finalBalance, amountIn);
    // }

    function testStaking() public {
        uint256 amountIn = 1 ether;

        bytes memory protocolData = abi.encodePacked(
            BOB,
            RestrictTransferFrom.TransferType.None,
            true,
            true
        );

        deal(address(LidoExposed), amountIn);
        LidoExposed.swap{value: amountIn}(amountIn, protocolData);

        uint256 finalBalance = IERC20(STETH_ADDR).balanceOf(
            address(LidoExposed)
        );
        // assertGe(finalBalance, amountIn);

        bytes memory protocolData2 = abi.encodePacked(
            BOB,
            RestrictTransferFrom.TransferType.None,
            false,
            true
        );

        // deal(STETH_ADDR, address(LidoExposed), amountIn);
        IERC20(STETH_ADDR).approve(WSTETH_ADDR, type(uint256).max);

        LidoExposed.swap(finalBalance, protocolData2);

        uint256 finalfinalBalance = IERC20(WSTETH_ADDR).balanceOf(
            address(LidoExposed)
        );
        assertGe(finalfinalBalance, finalBalance);
    }
}
