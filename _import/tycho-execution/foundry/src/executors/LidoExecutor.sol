// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {
    SafeERC20,
    IERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";

error LidoExecutor__InvalidDataLength();
error LidoExecutor__InvalidTarget();
error LidoExecutor__InvalidFactory();
error LidoExecutor__InvalidInitCode();
error LidoExecutor__InvalidFee();
error LidoExecutor__InvalidSwapDirection();
error LidoExecutor__ZeroAddress();

interface LidoPool {
    function submit(address referral) external payable returns (uint256);
}

interface LidoWrappedPool {
    function wrap(uint256 stEthAmount) external returns (uint256);

    function unwrap(uint256 wstEthAmount) external returns (uint256);
}

enum LidoPoolType {
    stETH,
    wstETH
}

enum LidoPoolDirection {
    Stake,
    Wrap,
    Unwrap
}

contract LidoExecutor is IExecutor {
    using SafeERC20 for IERC20;

    IERC20 public immutable stEth;
    address public immutable stEthAddress;
    address public immutable wstEthAddress;

    constructor(address stEthAddress_, address wstEthAddress_) {
        if (stEthAddress_ == address(0) || wstEthAddress_ == address(0)) {
            revert LidoExecutor__ZeroAddress();
        }
        stEth = IERC20(stEthAddress_);
        stEthAddress = stEthAddress_;
        wstEthAddress = wstEthAddress_;
    }

    function fundsExpectedAddress(
        bytes calldata /* data */
    )
        external
        view
        returns (address receiver)
    {
        return msg.sender;
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data, address receiver)
        external
        payable
        returns (uint256 amountOut, address tokenOut)
    {
        LidoPoolType pool;
        LidoPoolDirection direction;

        (pool, direction) = _decodeData(data);

        if (pool == LidoPoolType.stETH && direction == LidoPoolDirection.Stake)
        {
            // ST_ETH staking: ETH -> ST_ETH
            tokenOut = stEthAddress;
            // ST_ETH is a rebasing token where balances are calculated from shares
            // Measure actual balance changes to account for rounding in share conversions
            uint256 balanceBefore = stEth.balanceOf(address(this));

            // slither-disable-next-line arbitrary-send-eth,unused-return
            LidoPool(stEthAddress).submit{value: amountIn}(address(this));

            uint256 balanceAfter = stEth.balanceOf(address(this));
            amountOut = balanceAfter - balanceBefore;

            // submit() sends ST_ETH to this contract, transfer to receiver if needed
            if (receiver != address(this)) {
                uint256 receiverBalanceBefore = stEth.balanceOf(receiver);

                stEth.safeTransfer(receiver, amountOut);

                uint256 receiverBalanceAfter = stEth.balanceOf(receiver);
                // Update amountOut to reflect actual tokens received after transfer
                // (accounts for additional rounding during transfer)
                amountOut = receiverBalanceAfter - receiverBalanceBefore;
            }
        } else if (
            pool == LidoPoolType.wstETH && direction == LidoPoolDirection.Wrap
        ) {
            // WST_ETH wrapping: ST_ETH -> WST_ETH
            tokenOut = wstEthAddress;
            amountOut = LidoWrappedPool(wstEthAddress).wrap(amountIn);

            if (receiver != address(this)) {
                IERC20(wstEthAddress).safeTransfer(receiver, amountOut);
            }
        } else if (
            pool == LidoPoolType.wstETH && direction == LidoPoolDirection.Unwrap
        ) {
            tokenOut = stEthAddress;
            // WST_ETH unwrapping: WST_ETH -> ST_ETH
            amountOut = LidoWrappedPool(wstEthAddress).unwrap(amountIn);
            if (receiver != address(this)) {
                uint256 receiverBalanceBefore = stEth.balanceOf(receiver);
                stEth.safeTransfer(receiver, amountOut);
                uint256 receiverBalanceAfter = stEth.balanceOf(receiver);
                // Update amountOut to reflect actual tokens received after transfer
                // (accounts for additional rounding during transfer)
                amountOut = receiverBalanceAfter - receiverBalanceBefore;
            }
        } else {
            revert LidoExecutor__InvalidSwapDirection();
        }
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (LidoPoolType pool, LidoPoolDirection direction)
    {
        if (data.length != 2) {
            revert LidoExecutor__InvalidDataLength();
        }

        pool = LidoPoolType(uint8(data[0]));
        direction = LidoPoolDirection(uint8(data[1]));
    }

    function getTransferData(bytes calldata data)
        external
        payable
        returns (
            RestrictTransferFrom.TransferType transferType,
            address receiver,
            address tokenIn
        )
    {
        if (data.length != 2) {
            revert LidoExecutor__InvalidDataLength();
        }

        LidoPoolType pool = LidoPoolType(uint8(data[0]));
        LidoPoolDirection direction = LidoPoolDirection(uint8(data[1]));

        if (pool == LidoPoolType.stETH && direction == LidoPoolDirection.Stake)
        {
            // ST_ETH staking: ETH -> ST_ETH
            // ETH transfers are handled in the Executor, so we need to set the transferType to TransferNativeInExecutor
            // to update the delta accounting accordingly.
            tokenIn = address(0);
            transferType =
            RestrictTransferFrom.TransferType.TransferNativeInExecutor;
            // The token in is ETH in this case so we don't really need a receiver
        } else if (
            pool == LidoPoolType.wstETH && direction == LidoPoolDirection.Wrap
        ) {
            // WST_ETH wrapping: ST_ETH -> WST_ETH
            tokenIn = stEthAddress;
            transferType = RestrictTransferFrom.TransferType.ProtocolWillDebit;
            // The receiver of the funds will be the wstEth contract.
            receiver = wstEthAddress;
        } else if (
            pool == LidoPoolType.wstETH && direction == LidoPoolDirection.Unwrap
        ) {
            // WST_ETH unwrapping: WST_ETH -> ST_ETH
            tokenIn = wstEthAddress;
            transferType = RestrictTransferFrom.TransferType.ProtocolWillDebit;
            // The receiver needs to be TychoRouter because the wstETH contract will burn it from the msg.sender
            receiver = address(this);
        } else {
            revert LidoExecutor__InvalidSwapDirection();
        }
    }
}
