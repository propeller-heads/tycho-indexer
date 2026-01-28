// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/UniswapV4Executor.sol";
import {TychoRouter} from "@src/TychoRouter.sol";
import {
    Vault__UnexpectedInputDelta,
    Vault__UnexpectedNonZeroCount,
    ERC6909
} from "@src/Vault.sol";
import {
    RestrictTransferFrom__DifferentTokenIn
} from "@src/RestrictTransferFrom.sol";
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

    function protocolType() external returns (ProtocolType) {
        return ProtocolType.FundsInRouter;
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data, address receiver)
        external
        payable
        returns (uint256 amountOut, address tokenOut)
    {
        address tokenIn;
        (tokenIn,) = _decodeData(data);

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
        returns (address tokenIn, address)
    {
        tokenIn = address(bytes20(data[0:20]));
        return (tokenIn, address(0)); // receiver is no longer encoded in data
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
        receiver = address(0); // receiver is no longer encoded in data

        if (tokenIn == address(weth)) {
            // WETH -> ETH: Unwrap, transfer WETH to executor
            transferType = RestrictTransferFrom.TransferType.Transfer;
        } else {
            // ETH -> WETH: Wrap, transfer ETH via msg.value
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
    function testSplitSwapUsesVaultBalance() public {
        // A correctly encoded split swap uses vault's funds
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
            encodeUniswapV2Swap(WETH_WBTC_POOL, false)
        );

        // WETH -> WBTC (40%)
        swaps[1] = encodeSplitSwap(
            uint8(0),
            uint8(1),
            0, // 40%
            address(usv2Executor),
            encodeUniswapV2Swap(WETH_WBTC_POOL, false)
        );

        uint256 amountIn = 1 ether;
        uint256 existingVaultBalance = 3 ether;
        deal(WETH_ADDR, ALICE, amountIn + existingVaultBalance);

        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(tychoRouterAddr, existingVaultBalance);
        tychoRouter.deposit(WETH_ADDR, existingVaultBalance);

        uint256 amountOut = tychoRouter.splitSwapUsingVault(
            amountIn,
            WETH_ADDR,
            WBTC_ADDR,
            1, // min amount
            4,
            ALICE, // receiver
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
                uint8(1) // isDeposit = true
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
            0,
            address(0),
            0,
            _rocketpoolEthRethSwap()
        );
        vm.stopPrank();

        // Alice should have received rETH
        assertEq(amountOut, 883252117460416988);
        assertEq(IERC20(RETH_ADDR).balanceOf(ALICE), amountOut);

        // Alice's ETH vault balance should NOT be touched (still has 2 ether)
        assertEq(tychoRouterAddr.balance, existingVaultBalance);
        assertEq(tychoRouter.balanceOf(ALICE, 0), existingVaultBalance);
    }

    function testTransferNativeInExecutorForgotToSendETH() public {
        // Alice wants to swap ETH but forgets to send it via msg.value
        // Even though she has vault balance, the regular method should revert
        // (vault should only be used with explicit vault methods)
        uint256 amountIn = 1 ether;
        uint256 existingVaultBalance = 2 ether;
        deal(ALICE, existingVaultBalance);

        vm.startPrank(ALICE);
        tychoRouter.deposit{value: existingVaultBalance}(
            address(0), existingVaultBalance
        );
        vm.expectRevert(
            abi.encodeWithSelector(Vault__UnexpectedNonZeroCount.selector, 1)
        );
        tychoRouter.singleSwap( // No msg.value sent!
            amountIn,
            address(0), // ETH
            RETH_ADDR,
            1, // min amount
            ALICE, // receiver
            0,
            address(0),
            0,
            _rocketpoolEthRethSwap()
        );
        vm.stopPrank();
    }

    function testUseNativeVaultBalance() public {
        // First swap is native ETH transfer using vault balance

        uint256 amountIn = 1 ether;
        deal(ALICE, amountIn);

        vm.startPrank(ALICE);
        // Deposit ETH to vault
        tychoRouter.deposit{value: amountIn}(address(0), amountIn);

        uint256 amountOut = tychoRouter.singleSwapUsingVault(
            amountIn,
            address(0), // ETH
            RETH_ADDR,
            1, // min amount
            ALICE, // receiver
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

    function testVaultMethodWithMsgValue() public {
        // Alice calls vault method but sends ETH via msg.value - should revert
        uint256 amountIn = 1 ether;
        uint256 existingVaultBalance = 2 ether;
        deal(ALICE, amountIn + existingVaultBalance);

        vm.startPrank(ALICE);
        tychoRouter.deposit{value: existingVaultBalance}(
            address(0), existingVaultBalance
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                TychoRouter__MsgValueNotAllowedWithVaultMethod.selector,
                amountIn
            )
        );
        tychoRouter.singleSwapUsingVault{value: amountIn}(
            amountIn,
            address(0), // ETH
            RETH_ADDR,
            1, // min amount
            ALICE, // receiver
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
            bytes2(uint16(0)), // hook data length
            bytes("") // hook data
        );

        bytes memory protocolData = abi.encodePacked(
            USDC_ADDR,
            address(0), // ETH_ADDR
            false,
            pool
        );

        swaps[0] = encodeSingleSwap(address(usv4Executor), protocolData);

        // Second swap: ETH -> rETH (use credit from first swap)
        swaps[1] = _rocketpoolEthRethSwap();

        uint256 amountIn = 1 ether;
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

    function testSequentialCyclicSwapAndVaultIntegration() public {
        // USDC -> WETH -> USDC  using two pools and vault's funds
        uint256 amountIn = 100 * 10 ** 6;
        deal(USDC_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(tychoRouterAddr, type(uint256).max);
        tychoRouter.deposit(USDC_ADDR, amountIn);
        bytes memory callData = loadCallDataFromFile(
            "test_sequential_strategy_cyclic_swap_and_vault"
        );
        (bool success,) = tychoRouterAddr.call(callData);

        assertTrue(success, "Call Failed");
        assertEq(IERC20(USDC_ADDR).balanceOf(ALICE), 99792554);

        vm.stopPrank();
    }
}
