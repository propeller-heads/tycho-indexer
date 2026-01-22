// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/UniswapV4Executor.sol";
import {TychoRouter} from "@src/TychoRouter.sol";
import {
    RestrictTransferFrom__ExceededTransferFromAllowance,
    RestrictTransferFrom__DifferentTokenIn
} from "@src/RestrictTransferFrom.sol";
import {Vault__UnexpectedInputDelta, ERC6909} from "@src/Vault.sol";
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
        // from the user's wallet. The user has accidentally allowed MAX - REVERT

        //          ->   WBTC
        // 1 WETH
        //          ->   WBTC
        //       (univ2)
        bytes[] memory swaps = new bytes[](2);

        // WETH -> WBTC (60%)
        swaps[0] = encodeSplitSwap(
            uint8(0),
            uint8(1),
            uint24((0xffffff * 60) / 100), // 60%
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
            uint24((0xffffff * 60) / 100), // 60%
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

/**
 * @title TychoRouterTransferTest
 * @notice Test cases for Transfer type in the router (Transfer, TransferFromAndProtocolWillDebit, etc.)
 * @dev Tests various malicious scenarios and proper vault usage
 */
contract TychoRouterTransferTest is TychoRouterTestSetup {
    function testPreviousSwapReceiverWrongfullyEncoded() public {
        // Malicious encoding: previous swap receiver was wrongfully encoded to be
        // the current protocol instead of our router - REVERT
        // Sequential swap: WETH -> DAI -> USDC
        // First swap sends to DAI pool (malicious) instead of router
        // Second swap expects funds in the delta accounting but they're not there

        bytes[] memory swaps = new bytes[](2);

        // WETH -> DAI (malicious: receiver is DAI_USDC_POOL instead of router)
        swaps[0] = encodeSequentialSwap(
            address(usv2Executor),
            encodeUniswapV2Swap(
                DAI_WETH_UNIV2_POOL,
                DAI_USDC_POOL, // MALICIOUS: should be tychoRouterAddr
                false,
                RestrictTransferFrom.TransferType.TransferFrom
            )
        );

        // DAI -> USDC (expects Transfer from router, but funds are in pool)
        swaps[1] = encodeSequentialSwap(
            address(usv2Executor),
            encodeUniswapV2Swap(
                DAI_USDC_POOL,
                ALICE,
                true,
                RestrictTransferFrom.TransferType.Transfer
            )
        );

        uint256 amountIn = 1 ether;
        uint256 existingDaiVaultBalance = 3000 ether; // 3000 DAI
        deal(WETH_ADDR, ALICE, amountIn);

        // Alice does have some DAI in the vault. We must make sure not to use it,
        // since Alice didn't explicitly give us permission.
        deal(DAI_ADDR, ALICE, existingDaiVaultBalance);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, amountIn);
        IERC20(DAI_ADDR).approve(tychoRouterAddr, existingDaiVaultBalance);
        tychoRouter.deposit(DAI_ADDR, existingDaiVaultBalance);

        // Should revert because this causes a negative input delta for DAI
        // The only permitted negative input delta should be the input token, which
        // has a 0 delta, since we took funds straight form Alice's wallet and not
        // the vault.
        vm.expectRevert(
            abi.encodeWithSelector(Vault__UnexpectedInputDelta.selector, 0)
        );
        tychoRouter.sequentialSwap(
            amountIn,
            WETH_ADDR,
            USDC_ADDR,
            1, // min amount
            ALICE,
            true,
            0,
            address(0),
            0,
            pleEncode(swaps)
        );
        vm.stopPrank();
    }

    function testSplitSwapUsesVaultBalance() public {
        // A maliciously encoded split swap attempts to take more than the input amount
        // from the user's vault - REVERT

        //          ->   WBTC (60%)
        // 1 WETH
        //          ->   WBTC (40%)
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
                RestrictTransferFrom.TransferType.Transfer
            )
        );

        // WETH -> WBTC (40%)
        swaps[1] = encodeSplitSwap(
            uint8(0),
            uint8(1),
            0, // 40%
            address(usv2Executor),
            encodeUniswapV2Swap(
                WETH_WBTC_POOL,
                tychoRouterAddr,
                false,
                RestrictTransferFrom.TransferType.Transfer
            )
        );

        uint256 amountIn = 1 ether;
        uint256 existingVaultBalance = 3 ether;
        deal(WETH_ADDR, ALICE, amountIn + existingVaultBalance);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, existingVaultBalance);
        tychoRouter.deposit(WETH_ADDR, existingVaultBalance);

        uint256 amountOut = tychoRouter.splitSwap(
            amountIn,
            WETH_ADDR,
            WBTC_ADDR,
            1, // min amount
            4,
            ALICE, // receiver
            false, // no transferFrom
            0,
            address(0),
            0,
            pleEncode(swaps)
        );
        vm.stopPrank();

        // 1 ether was used from vault balance. The rest (2 ether) remains.
        assertEq(
            tychoRouter.balanceOf(ALICE, uint256(uint160(WETH_ADDR))), 2 ether
        );
        // Alice received the amount out
        assertEq(IERC20(WBTC_ADDR).balanceOf(ALICE), amountOut);
    }

    function testWrongInputTokenFirstSwap() public {
        // User sends native ETH with the swap, but first pool maliciously encodes a
        // different input token in an attempt to use the user’s vault balance of
        // another token

        bytes memory swap = encodeSingleSwap(
            address(usv2Executor),
            encodeUniswapV2Swap(
                USDC_WETH_USV2,
                tychoRouterAddr,
                false, // swap WETH for USDC
                RestrictTransferFrom.TransferType.Transfer
            )
        );

        uint256 amountIn = 1 ether;
        deal(ALICE, amountIn);
        deal(WETH_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, amountIn);

        // Alice has WETH in vault that the malicious encoder is trying to steal
        tychoRouter.deposit(WETH_ADDR, amountIn);

        // The router only allows using vault funds for the initial tokenIn, preventing
        // vault theft
        vm.expectRevert(
            abi.encodeWithSelector(
                Vault__UnexpectedInputDelta.selector, 1000000000000000000
            )
        );
        tychoRouter.singleSwap{value: amountIn}(
            amountIn,
            address(0), // ETH
            DAI_ADDR,
            1, // min amount
            ALICE, // receiver
            false, // transferFrom allowed
            0, // solverFeeBps
            address(0), // solverFeeReceiver
            0, // maxSolverContribution
            swap
        );
        vm.stopPrank();
    }

    function testMsgValueDoesNotMatchAmountIn() public {
        // Alice transfers in 1 ETH (to use in her swap) via msg.value.
        // By accident, she specified 2 ETH as her input amount. This does not match
        // the amount that she sent - revert.
        uint256 amountIn = 1 ether;
        deal(ALICE, amountIn);

        bytes memory swap = new bytes(0); // IRRELEVANT - should fail before this

        vm.startPrank(ALICE);
        vm.expectRevert(
            abi.encodeWithSelector(
                TychoRouter__MsgValueDoesNotMatchAmountIn.selector,
                amountIn - 1,
                amountIn
            )
        );
        tychoRouter.singleSwap{value: amountIn - 1}(
            amountIn,
            address(0), // ETH
            DAI_ADDR,
            1, // min amount
            ALICE, // receiver
            false, // transferFrom allowed
            0, // solverFeeBps
            address(0), // solverFeeReceiver
            0, // maxSolverContribution
            swap
        );
        vm.stopPrank();
    }
}

/**
 * @title TychoRouterTransferNativeInMsgValueTest
 * @notice Test cases for TransferNativeInMsgValue transfer type
 * @dev Tests native ETH transfers via msg.value to protocols
 */
contract TychoRouterTransferNativeInMsgValueTest is TychoRouterTestSetup {
    function _rocketpoolEthRethSwap() private returns (bytes memory swap) {
        swap = encodeSingleSwap(
            address(rocketpoolExecutor),
            abi.encodePacked(
                uint8(1), // isDeposit = true
                uint8(0), // transferType (ignored for deposits - hardcoded in executor)
                tychoRouterAddr // receiver (router will handle final transfer to ALICE)
            )
        );
    }

    function testTransferNativeInMsgValueUserSentETH() public {
        // First swap is native ETH transfer (in msg value), user sent ETH
        // ETH -> rETH via Rocketpool deposit
        uint256 amountIn = 1 ether;
        uint256 existingVaultBalance = 2 ether;
        deal(ALICE, amountIn + existingVaultBalance);

        vm.startPrank(ALICE);
        tychoRouter.deposit{value: existingVaultBalance}(
            address(0), existingVaultBalance
        );
        uint256 amountOut = tychoRouter.singleSwap{value: amountIn}(
            amountIn,
            address(0), // ETH
            RETH_ADDR,
            1, // min amount
            ALICE, // receiver
            false, // no transferFrom
            0,
            address(0),
            0,
            _rocketpoolEthRethSwap()
        );
        vm.stopPrank();

        // Alice should have received rETH
        assertEq(amountOut, 883252117460416988);
        assertEq(IERC20(RETH_ADDR).balanceOf(ALICE), amountOut);

        // Alice's ETH vault balance should be spent
        assertEq(tychoRouterAddr.balance, existingVaultBalance);
        assertEq(tychoRouter.balanceOf(ALICE, 0), existingVaultBalance);
    }

    function testTransferNativeInMsgValueUsesVaultBalance() public {
        // First swap is native ETH transfer (in msg value), user didn't send ETH,
        // so their vault balance is used

        // TODO what if the user just forgets to send ETH here and didn’t expect
        // their vault balance to be used. Is this okay that this isn't so explicit?

        uint256 amountIn = 1 ether;
        deal(ALICE, amountIn);

        vm.startPrank(ALICE);
        // Deposit ETH to vault
        tychoRouter.deposit{value: amountIn}(address(0), amountIn);

        // Call without msg.value - should use vault balance
        uint256 amountOut = tychoRouter.singleSwap(
            amountIn,
            address(0), // ETH
            RETH_ADDR,
            1, // min amount
            ALICE, // receiver
            false, // no transferFrom
            0,
            address(0),
            0,
            _rocketpoolEthRethSwap()
        );
        vm.stopPrank();

        // Alice should have received rETH
        assertGt(IERC20(RETH_ADDR).balanceOf(ALICE), 0);
        assertEq(IERC20(RETH_ADDR).balanceOf(ALICE), amountOut);

        // Vault balance should be zero
        assertEq(tychoRouter.balanceOf(ALICE, 0), 0);
    }

    function testTransferNativeInMsgValueNoVaultBalance() public {
        // First swap is native ETH transfer (in msg value), user didn't send ETH
        // and had no vault balance - REVERT
        uint256 amountIn = 1 ether;
        vm.startPrank(ALICE);
        // Router has funds - none of which belong to Alice so she can't use them.
        deal(tychoRouterAddr, 500 ether);
        vm.expectRevert(
            abi.encodeWithSelector(
                ERC6909.ERC6909InsufficientBalance.selector,
                0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2,
                0,
                1e18,
                0
            )
        );
        tychoRouter.singleSwap(
            amountIn,
            address(0), // ETH
            RETH_ADDR,
            1, // min amount
            ALICE, // receiver
            false, // no transferFrom
            0,
            address(0),
            0,
            _rocketpoolEthRethSwap()
        );
        vm.stopPrank();
    }

    function testSequentialSwapNativeETHCredit() public {
        // Output of first swap is native ETH. Second swap successfully uses the
        // credit to perform a native ETH input swap without touching vault funds.
        // Sequential swap: USDC --(USV4)--> ETH --(rocket)--> rETH
        bytes[] memory swaps = new bytes[](2);

        // First swap: USDC -> ETH
        bytes memory pool = abi.encodePacked(
            address(0), // intermediary token
            bytes3(uint24(3000)), // fee
            int24(60), // tick spacing
            address(0), // hook
            bytes2(uint16(0)), // hookdata length
            bytes("") // hookdate
        );

        bytes memory protocolData = abi.encodePacked(
            USDC_ADDR,
            address(0), // ETH_ADDR,
            false, // zero for one ?? i dont know
            RestrictTransferFrom.TransferType.TransferFrom,
            address(tychoRouter), // receiver
            pool
        );

        swaps[0] = encodeSingleSwap(address(usv4Executor), protocolData);

        // Second swap: ETH -> rETH (use credit from first swap)
        swaps[1] = _rocketpoolEthRethSwap();

        uint256 amountIn = 1 ether; // ezETH
        uint256 existingVaultETHBalance = 3 ether;

        deal(USDC_ADDR, ALICE, amountIn);
        deal(ALICE, existingVaultETHBalance);

        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(tychoRouterAddr, amountIn);

        tychoRouter.deposit{value: existingVaultETHBalance}(
            address(0), existingVaultETHBalance
        );

        uint256 amountOut = tychoRouter.sequentialSwap(
            amountIn,
            USDC_ADDR,
            RETH_ADDR,
            1, // min amount
            ALICE, // receiver
            true, // transferFrom
            0, // solver fee bps
            address(0), // solver fee receiver
            0, // max solver contribution
            pleEncode(swaps)
        );
        vm.stopPrank();

        // Alice should have received rETH from the last swap
        assertEq(amountOut, 258732654855663419141);
        assertEq(IERC20(RETH_ADDR).balanceOf(ALICE), amountOut);

        // Router ETH balance should not have changed
        assertEq(address(tychoRouter).balance, existingVaultETHBalance);
        assertEq(tychoRouter.balanceOf(ALICE, 0), existingVaultETHBalance);
    }
}
