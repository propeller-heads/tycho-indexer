// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/UniswapV4Executor.sol";
import {TychoRouter} from "@src/TychoRouter.sol";
import {
    Vault__UnexpectedInputDelta,
    Vault__UnexpectedNonZeroCount,
    ERC6909
} from "@src/Vault.sol";
import {IExecutor} from "@interfaces/IExecutor.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {IWETH} from "../lib/IWETH.sol";
import "./TychoRouterTestSetup.sol";

/**
 * @title WrapUnwrapExecutor
 * @notice Mock executor that wraps/unwraps ETH <-> WETH
 * @dev Used for testing circular swaps with native ETH
 */
contract WrapUnwrapExecutor is IExecutor {
    using SafeERC20 for IWETH;
    using SafeERC20 for IERC20;

    IWETH public immutable weth;

    constructor(address _weth) {
        weth = IWETH(_weth);
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 amountOut, address tokenOut, address receiver)
    {
        address tokenIn;
        (tokenIn, receiver) = _decodeData(data);

        if (tokenIn == address(weth)) {
            // WETH -> ETH: Unwrap
            weth.withdraw(amountIn);
            amountOut = amountIn;
            tokenOut = address(0);

            if (receiver != address(this)) {
                Address.sendValue(payable(receiver), amountOut);
            }
        } else {
            // ETH -> WETH: Wrap
            weth.deposit{value: amountIn}();
            amountOut = amountIn;
            tokenOut = address(weth);

            if (receiver != address(this)) {
                weth.safeTransfer(receiver, amountOut);
            }
        }
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (address tokenIn, address receiver)
    {
        tokenIn = address(bytes20(data[0:20]));
        receiver = address(bytes20(data[20:40]));
    }

    /// @dev Required to receive ETH
    receive() external payable {}

    function getTransferData(bytes calldata data)
        external
        payable
        returns (
            RestrictTransferFrom.TransferType transferType,
            address receiver,
            address tokenIn
        )
    {
        tokenIn = address(bytes20(data[0:20]));
        receiver = address(bytes20(data[20:40]));

        if (tokenIn == address(weth)) {
            transferType = RestrictTransferFrom.TransferType(uint8(data[40]));
        } else {
            // ETH -> WETH: Need to transfer ETH via msg.value
            transferType =
            RestrictTransferFrom.TransferType.TransferNativeInExecutor;
        }
    }
}

/**
 * @title TychoRouterUsingVaultTest
 * @notice Test cases for different swap scenarios relating to the Vault
 */
contract TychoRouterUsingVaultTest is TychoRouterTestSetup {
    // ==================== Transfer tests ====================

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
                tychoRouterAddr,
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

        // Should revert because this causes a negative delta for DAI
        // When using InputSource.TransferFrom, no negative deltas are allowed
        vm.expectRevert(
            abi.encodeWithSelector(Vault__UnexpectedNonZeroCount.selector, 1)
        );
        tychoRouter.sequentialSwap(
            amountIn,
            WETH_ADDR,
            USDC_ADDR,
            1, // min amount
            ALICE,
            RestrictTransferFrom.InputSource.TransferFrom,
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
            RestrictTransferFrom.InputSource.Vault,
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
        // vault theft but even before this, it checks for the amount of NonZeroCount
        //which in this case will be 2: one for positive for ETH and one negative for WETH
        vm.expectRevert(
            abi.encodeWithSelector(Vault__UnexpectedNonZeroCount.selector, 2)
        );
        tychoRouter.singleSwap{value: amountIn}(
            amountIn,
            address(0), // ETH
            USDC_ADDR,
            1, // min amount
            ALICE, // receiver
            RestrictTransferFrom.InputSource.Vault,
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
            RestrictTransferFrom.InputSource.Vault,
            0, // solverFeeBps
            address(0), // solverFeeReceiver
            0, // maxSolverContribution
            swap
        );
        vm.stopPrank();
    }

    // ==================== Native Transfer tests ====================
    function _rocketpoolEthRethSwap() private view returns (bytes memory swap) {
        swap = encodeSingleSwap(
            address(rocketpoolExecutor),
            abi.encodePacked(
                uint8(1), // isDeposit = true
                uint8(0), // transferType (ignored for deposits - hardcoded in executor)
                tychoRouterAddr // receiver (router will handle final transfer to ALICE)
            )
        );
    }

    function testTransferNativeInExecutorUserSentETH() public {
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
            RestrictTransferFrom.InputSource.Vault,
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

    function testTransferNativeInExecutorUsesVaultBalance() public {
        // First swap is native ETH transfer (in msg value), user didn't send ETH,
        // so their vault balance is used

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
            RestrictTransferFrom.InputSource.Vault,
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

    function testTransferNativeInExecutorNoVaultBalance() public {
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
            RestrictTransferFrom.InputSource.Vault,
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
            RestrictTransferFrom.InputSource.TransferFrom,
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

    // ==================== ProtocolWillDebit tests ====================

    function testProtocolWillDebitWrongPreviousReceiver() public {
        // Previous swap receiver was wrongfully encoded to be the current protocol
        // instead of the router - REVERT
        // Sequential swap: WETH -> DAI -> USDC
        // First swap sends to Curve TRIPOOL instead of router
        // Second swap expects funds in the router via ProtocolWillDebit but they're not there

        bytes[] memory swaps = new bytes[](2);

        // WETH -> DAI (malicious: receiver is TRIPOOL instead of router)
        swaps[0] = encodeSequentialSwap(
            address(usv2Executor),
            encodeUniswapV2Swap(
                DAI_WETH_UNIV2_POOL,
                TRIPOOL, // MALICIOUS: should be tychoRouterAddr
                false,
                RestrictTransferFrom.TransferType.TransferFrom
            )
        );

        // DAI -> USDC on Curve TRIPOOL
        swaps[1] = encodeSequentialSwap(
            address(curveExecutor),
            abi.encodePacked(
                DAI_ADDR, // tokenIn
                USDC_ADDR, // tokenOut
                TRIPOOL, // pool
                uint8(1), // poolType (1 for StableSwap)
                uint8(0), // i (DAI index)
                uint8(1), // j (USDC index)
                RestrictTransferFrom.TransferType.ProtocolWillDebit,
                tychoRouterAddr // receiver
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

        // Should revert because this causes a negative delta for DAI
        // When using InputSource.TransferFrom, no negative deltas are allowed
        vm.expectRevert(
            abi.encodeWithSelector(Vault__UnexpectedNonZeroCount.selector, 1)
        );
        tychoRouter.sequentialSwap(
            amountIn,
            WETH_ADDR,
            USDC_ADDR,
            1, // min amount
            ALICE,
            RestrictTransferFrom.InputSource.TransferFrom,
            0,
            address(0),
            0,
            pleEncode(swaps)
        );
        vm.stopPrank();
    }

    function testTransferNoneForProtocolWillDebit() public {
        // Alice attempts to use vault funds that don't belong to her by encoding
        // None transfer type when it should be ProtocolWillDebit. When Curve attempts
        // to take the tokens, it fails due to insufficient allowance.

        // DAI -> USDC on Curve TRIPOOL
        bytes memory swap = encodeSingleSwap(
            address(curveExecutor),
            abi.encodePacked(
                DAI_ADDR, // tokenIn
                USDC_ADDR, // tokenOut
                TRIPOOL, // pool
                uint8(1), // poolType (1 for StableSwap)
                uint8(0), // i (DAI index)
                uint8(1), // j (USDC index)
                RestrictTransferFrom.TransferType.None, // Should be ProtocolWillDebit
                ALICE // receiver
            )
        );

        uint256 amountIn = 1000 ether;
        uint256 existingDaiRouterBalance = 3000 ether; // 3000 DAI
        deal(DAI_ADDR, tychoRouterAddr, existingDaiRouterBalance);

        vm.startPrank(ALICE);
        // This reverts with Dai/insufficient-allowance - though the low-level error
        // is caught as "ExecutionReverted" in the Dispatcher.
        vm.expectRevert();
        tychoRouter.singleSwap(
            amountIn,
            WETH_ADDR,
            USDC_ADDR,
            1, // min amount
            ALICE, // receiver
            RestrictTransferFrom.InputSource.Vault,
            0, // solver fee bps
            address(0), // solver fee receiver
            0, // max solver contribution
            swap
        );
        vm.stopPrank();
    }

    function testProtocolWillDebitFromVaultIntegration() public {
        // Integration test for ProtocolWillDebit with Curve where funds are taken from
        // user's vault in the first swap.
        //
        // This test:
        // 1. Deposits DAI to Alice's vault
        // 2. Executes a single swap: DAI (from vault) -> (Curve TriPool) -> USDC
        // 3. Verifies funds were successfully taken from vault and swap executed
        // 4. Uses calldata generated from Rust encoding test

        uint256 amountIn = 1000 ether; // 1000 DAI
        uint256 vaultBalance = 3000 ether; // Alice starts with 3000 DAI in vault

        deal(DAI_ADDR, ALICE, vaultBalance);

        vm.startPrank(ALICE);
        IERC20(DAI_ADDR).approve(tychoRouterAddr, vaultBalance);
        tychoRouter.deposit(DAI_ADDR, vaultBalance);
        bytes memory calldata_ = loadCallDataFromFile(
            "test_single_encoding_strategy_curve_protocol_will_debit_from_vault"
        );

        (bool success,) = address(tychoRouter).call(calldata_);
        require(success, "Swap failed");

        vm.stopPrank();

        assertEq(
            tychoRouter.balanceOf(ALICE, uint256(uint160(DAI_ADDR))),
            vaultBalance - amountIn
        );

        assertEq(IERC20(USDC_ADDR).balanceOf(ALICE), 999821834);
    }

    // ==================== Circular Vault tests ====================

    WrapUnwrapExecutor public wrapUnwrapExecutor;

    function setUp() public override {
        super.setUp();
        wrapUnwrapExecutor = new WrapUnwrapExecutor(WETH_ADDR);

        // Add wrapUnwrapExecutor to allowed executors
        address[] memory executors = new address[](1);
        executors[0] = address(wrapUnwrapExecutor);
        vm.startPrank(EXECUTOR_SETTER);
        tychoRouter.setExecutors(executors);
        vm.stopPrank();
    }

    function testCircularSwapCannotStealETH() public {
        // Circular swap: ETH -> WETH -> ETH -> rETH
        //
        // Alice didn't realize that she is actually using Bob the malicious encoder.
        // She believed in a trust-less encoding system and failed to check her own
        // calldata. Luckily, our guardrails protected her.
        //
        // 1. Alice sends 1 ETH to the router. Delta accounting for ETH is 1
        // 2. Alice swaps ETH to WETH. Delta accounting for ETH is 0.
        // 3. Alice swaps WETH to ETH, but Bob the malicious encoder set the receiver to
        //    himself. Delta accounting for ETH is 0 and for WETH is 1.
        // 4. The router sends ETH to rETH. Delta accounting for ETH is -1.
        // 5. Since we don't allow any non zero delta for the input amount (and for any other amount), the
        //    transaction reverts, preventing Bob from stealing Alice's funds.
        bytes[] memory swaps = new bytes[](3);

        // Swap 1: ETH -> WETH (wrap)
        swaps[0] = encodeSequentialSwap(
            address(wrapUnwrapExecutor),
            abi.encodePacked(
                address(0), // tokenIn (ETH)
                tychoRouterAddr, // receiver
                RestrictTransferFrom.TransferType.Transfer
            )
        );

        // Swap 2: WETH -> ETH (unwrap)
        swaps[1] = encodeSequentialSwap(
            address(wrapUnwrapExecutor),
            abi.encodePacked(
                WETH_ADDR, // tokenIn
                BOB, // receiver - BOB maliciously encoded himself as the receiver,
                // stealing weth from Alice's Vault without her realizing
                RestrictTransferFrom.TransferType.None // This will be replaced with ProtocolWillDebit
            )
        );

        // Swap 3: WETH -> rETH (rocketpool)
        swaps[2] = _rocketpoolEthRethSwap();

        uint256 amountIn = 1 ether;
        deal(ALICE, amountIn * 2);

        vm.startPrank(ALICE);

        // Alice has 1 ETH in the vault, and 1 ETH in her own wallet for swapping.
        tychoRouter.deposit{value: amountIn}(address(0), amountIn);

        vm.expectRevert(
            abi.encodeWithSelector(Vault__UnexpectedNonZeroCount.selector, 2)
        );
        tychoRouter.sequentialSwap{value: amountIn}(
            amountIn,
            address(0), // in token
            RETH_ADDR,
            1, // min amount
            ALICE, // receiver
            RestrictTransferFrom.InputSource.TransferFrom,
            0, // solver fee bps
            address(0), // solver fee receiver
            0, // max solver contribution
            pleEncode(swaps)
        );
        vm.stopPrank();
    }
}
