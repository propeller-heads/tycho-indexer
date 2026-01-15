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

    IERC20 public immutable ST_ETH;
    address public immutable ST_ETH_ADDRESS;
    address public immutable WST_ETH;

    constructor(address _stEthAddress, address _wstEthAddress) {
        if (_stEthAddress == address(0) || _wstEthAddress == address(0)) {
            revert LidoExecutor__ZeroAddress();
        }
        ST_ETH = IERC20(_stEthAddress);
        ST_ETH_ADDRESS = _stEthAddress;
        WST_ETH = _wstEthAddress;
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount, address tokenOut, address receiver)
    {
        LidoPoolType pool;
        LidoPoolDirection direction;
        bool approvalNeeded;

        (receiver, pool, direction, approvalNeeded) = _decodeData(data);

        if (pool == LidoPoolType.stETH && direction == LidoPoolDirection.Stake)
        {
            tokenOut = ST_ETH_ADDRESS;
            // ST_ETH staking: ETH -> ST_ETH
            // ST_ETH is a rebasing token where balances are calculated from shares
            // Measure actual balance changes to account for rounding in share conversions
            uint256 balanceBefore = ST_ETH.balanceOf(address(this));

            // slither-disable-next-line arbitrary-send-eth
            uint256 shares =
                LidoPool(ST_ETH_ADDRESS).submit{value: amountIn}(address(this));

            uint256 balanceAfter = ST_ETH.balanceOf(address(this));
            calculatedAmount = balanceAfter - balanceBefore;

            // submit() sends ST_ETH to this contract, transfer to receiver if needed
            if (receiver != address(this)) {
                uint256 receiverBalanceBefore = ST_ETH.balanceOf(receiver);

                ST_ETH.safeTransfer(receiver, calculatedAmount);

                uint256 receiverBalanceAfter = ST_ETH.balanceOf(receiver);
                // Update calculatedAmount to reflect actual tokens received after transfer
                // (accounts for additional rounding during transfer)
                calculatedAmount = receiverBalanceAfter - receiverBalanceBefore;
            }
            tokenOut = ST_ETH_ADDRESS;
        } else if (
            pool == LidoPoolType.wstETH && direction == LidoPoolDirection.Wrap
        ) {
            tokenOut = WST_ETH;
            // WST_ETH wrapping: ST_ETH -> WST_ETH
            if (approvalNeeded) {
                ST_ETH.forceApprove(WST_ETH, type(uint256).max - 1);
            }
            calculatedAmount = LidoWrappedPool(WST_ETH).wrap(amountIn);

            if (receiver != address(this)) {
                IERC20(WST_ETH).safeTransfer(receiver, calculatedAmount);
            }
            tokenOut = WST_ETH;
        } else if (
            pool == LidoPoolType.wstETH && direction == LidoPoolDirection.Unwrap
        ) {
            tokenOut = ST_ETH_ADDRESS;
            // WST_ETH unwrapping: WST_ETH -> ST_ETH
            calculatedAmount = LidoWrappedPool(WST_ETH).unwrap(amountIn);
            if (receiver != address(this)) {
                uint256 receiverBalanceBefore = ST_ETH.balanceOf(receiver);
                ST_ETH.safeTransfer(receiver, calculatedAmount);
                uint256 receiverBalanceAfter = ST_ETH.balanceOf(receiver);
                // Update calculatedAmount to reflect actual tokens received after transfer
                // (accounts for additional rounding during transfer)
                calculatedAmount = receiverBalanceAfter - receiverBalanceBefore;
                tokenOut = ST_ETH_ADDRESS;
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

        transferType = RestrictTransferFrom.TransferType(uint8(data[20]));
        LidoPoolType pool = LidoPoolType(uint8(data[21]));
        LidoPoolDirection direction = LidoPoolDirection(uint8(data[22]));

        if (pool == LidoPoolType.stETH && direction == LidoPoolDirection.Stake)
        {
            // ST_ETH staking: ETH -> ST_ETH
            tokenIn = address(0);
        } else if (
            pool == LidoPoolType.wstETH && direction == LidoPoolDirection.Wrap
        ) {
            // WST_ETH wrapping: ST_ETH -> WST_ETH
            tokenIn = address(ST_ETH);
        } else if (
            pool == LidoPoolType.wstETH && direction == LidoPoolDirection.Unwrap
        ) {
            // WST_ETH unwrapping: WST_ETH -> ST_ETH
            tokenIn = address(WST_ETH);
        } else {
            revert LidoExecutor__InvalidSwapDirection();
        }

        // Since the WST_ETH contract withdraws the funds from the msg.sender, the user's funds need to sent to the
        // TychoRouter initially (address(this))
        receiver = address(this);
    }
}
