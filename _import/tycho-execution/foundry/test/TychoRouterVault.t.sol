// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/UniswapV4Executor.sol";
import {TychoRouter} from "@src/TychoRouter.sol";
import {
    RestrictTransferFrom__ExceededTransferFromAllowance
} from "@src/RestrictTransferFrom.sol";
import "./TychoRouterTestSetup.sol";

/**
 * @title TychoRouterTransferFromTest
 * @notice Test cases for the Vault
 * @dev TransferFrom transfers tokens directly from user wallet to protocol
 */
contract TychoRouterTransferFromTest is TychoRouterTestSetup {
    function testTransferFromExceedsRestriction() public {
        // TODO this isn't vault-specific - it checks our RestrictTransferFrom
        //  contract. should we move this to another file?

        // A maliciously encoded split swap attempts to take more than the input amount
        // from the user’s wallet. The user has accidentally allowed MAX - REVERT

        //          ->   WBTC
        // 1 WETH
        //          ->   WBTC
        //       (univ2)
        bytes[] memory swaps = new bytes[](2);

        // WETH -> WBTC (60%)
        swaps[0] = encodeSplitSwap(
            uint8(0),
            uint8(1),
            (0xffffff * 60) / 100, // 60%
            address(usv2Executor),
            encodeUniswapV2Swap(
                WETH_WBTC_POOL,
                tychoRouterAddr,
                false,
                RestrictTransferFrom.TransferType.TransferFrom
            )
        );
        // WETH -> WBTC (50%)
        swaps[1] = encodeSplitSwap(
            uint8(0),
            uint8(1),
            (0xffffff * 60) / 100, // 60%
            address(usv2Executor),
            encodeUniswapV2Swap(
                WETH_WBTC_POOL,
                tychoRouterAddr,
                false,
                RestrictTransferFrom.TransferType.TransferFrom
            )
        );

        uint256 amountIn = 100 ether;
        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        // Alice's mistake - too high approval. She should still be protected by our
        // router.
        IERC20(WETH_ADDR).approve(tychoRouterAddr, UINT256_MAX);

        vm.expectRevert(
            abi.encodeWithSelector(
                RestrictTransferFrom__ExceededTransferFromAllowance.selector,
                40000000000000000000,
                60000000000000000000
            )
        );
        tychoRouter.splitSwap(
            amountIn,
            WETH_ADDR,
            WBTC_ADDR,
            200_000000, // min amount (2 WBTC)
            4,
            ALICE,
            true,
            0,
            address(0),
            0, // max solver contribution
            pleEncode(swaps)
        );
    }
}
