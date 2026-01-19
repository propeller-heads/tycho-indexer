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
    address public immutable wstEth;

    constructor(address _stEthAddress, address _wstEthAddress) {
        if (_stEthAddress == address(0) || _wstEthAddress == address(0)) {
            revert LidoExecutor__ZeroAddress();
        }
        stEth = IERC20(_stEthAddress);
        stEthAddress = _stEthAddress;
        wstEth = _wstEthAddress;
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 amountOut, address tokenOut, address receiver)
    {
        LidoPoolType pool;
        LidoPoolDirection direction;
        bool approvalNeeded;

        (receiver, pool, direction, approvalNeeded) = _decodeData(data);

        if (pool == LidoPoolType.stETH && direction == LidoPoolDirection.Stake)
        {
            tokenOut = stEthAddress;
            // ST_ETH staking: ETH -> ST_ETH
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
            tokenOut = stEthAddress;
        } else if (
            pool == LidoPoolType.wstETH && direction == LidoPoolDirection.Wrap
        ) {
            tokenOut = wstEth;
            // WST_ETH wrapping: ST_ETH -> WST_ETH
            amountOut = LidoWrappedPool(wstEth).wrap(amountIn);

            if (receiver != address(this)) {
                IERC20(wstEth).safeTransfer(receiver, amountOut);
            }
            tokenOut = wstEth;
        } else if (
            pool == LidoPoolType.wstETH && direction == LidoPoolDirection.Unwrap
        ) {
            tokenOut = stEthAddress;
            // WST_ETH unwrapping: WST_ETH -> ST_ETH
            amountOut = LidoWrappedPool(wstEth).unwrap(amountIn);
            if (receiver != address(this)) {
                uint256 receiverBalanceBefore = stEth.balanceOf(receiver);
                stEth.safeTransfer(receiver, amountOut);
                uint256 receiverBalanceAfter = stEth.balanceOf(receiver);
                // Update amountOut to reflect actual tokens received after transfer
                // (accounts for additional rounding during transfer)
                amountOut = receiverBalanceAfter - receiverBalanceBefore;
                tokenOut = stEthAddress;
            }
        } else {
            revert LidoExecutor__InvalidSwapDirection();
        }
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            address receiver,
            LidoPoolType pool,
            LidoPoolDirection direction,
            bool approvalNeeded
        )
    {
        if (data.length != 24) {
            revert LidoExecutor__InvalidDataLength();
        }

        receiver = address(bytes20(data[0:20]));
        pool = LidoPoolType(uint8(data[21]));
        direction = LidoPoolDirection(uint8(data[22]));
        approvalNeeded = data[23] != 0;
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
        if (data.length != 24) {
            revert LidoExecutor__InvalidDataLength();
        }

        LidoPoolType pool = LidoPoolType(uint8(data[21]));
        LidoPoolDirection direction = LidoPoolDirection(uint8(data[22]));

        if (pool == LidoPoolType.stETH && direction == LidoPoolDirection.Stake)
        {
            // ST_ETH staking: ETH -> ST_ETH
            tokenIn = address(0);
            transferType =
            RestrictTransferFrom.TransferType.TransferNativeInMsgValue;
        } else if (
            pool == LidoPoolType.wstETH && direction == LidoPoolDirection.Wrap
        ) {
            // WST_ETH wrapping: ST_ETH -> WST_ETH
            tokenIn = stEthAddress;
            transferType = RestrictTransferFrom.TransferType(uint8(data[20]));
            // The receiver of the funds will be the wstEth contract.
            // This protocol will only ever have the following transferTypes:
            // - TransferFromAndProtocolWillDebit: the funds should be transferred to the TychoRouter and the wstEth contract needs to be approved
            // - ProtocolWillDebit: wstEth needs to be approved
            receiver = wstEth;
        } else if (
            pool == LidoPoolType.wstETH && direction == LidoPoolDirection.Unwrap
        ) {
            // WST_ETH unwrapping: WST_ETH -> ST_ETH
            tokenIn = wstEth;
            transferType = RestrictTransferFrom.TransferType(uint8(data[20]));
            // The receiver needs to be TychoRouter because the wstETH contract will burn it from the msg.sender
            receiver = address(this);
        } else {
            revert LidoExecutor__InvalidSwapDirection();
        }
    }
}
