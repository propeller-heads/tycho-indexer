// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
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
    // slither-disable-next-line naming-convention
    function wrap(uint256 _stETHAmount) external returns (uint256);

    function unwrap(uint256 _wstETHAmount) external returns (uint256);
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

contract LidoExecutor is IExecutor, RestrictTransferFrom {
    using SafeERC20 for IERC20;

    IERC20 public immutable stETH;
    address public immutable stETHAddress;
    address public immutable wstETH;

    constructor(address _stETHAddress, address _wstETHAddress, address _permit2)
        RestrictTransferFrom(_permit2)
    {
        if (_stETHAddress == address(0) || _wstETHAddress == address(0)) {
            revert LidoExecutor__ZeroAddress();
        }
        stETH = IERC20(_stETHAddress);
        stETHAddress = _stETHAddress;
        wstETH = _wstETHAddress;
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 givenAmount, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount)
    {
        address receiver;
        TransferType transferType;
        LidoPoolType pool;
        LidoPoolDirection direction;
        bool approvalNeeded;

        (receiver, transferType, pool, direction, approvalNeeded) =
            _decodeData(data);

        if (pool == LidoPoolType.stETH && direction == LidoPoolDirection.Stake)
        {
            // stETH staking: ETH -> stETH
            // stETH is a rebasing token where balances are calculated from shares
            // Measure actual balance changes to account for rounding in share conversions
            uint256 balanceBefore = stETH.balanceOf(address(this));

            // slither-disable-next-line arbitrary-send-eth
            uint256 _shares = LidoPool(stETHAddress).submit{value: givenAmount}(
                address(this)
            );

            uint256 balanceAfter = stETH.balanceOf(address(this));
            calculatedAmount = balanceAfter - balanceBefore;

            // submit() sends stETH to this contract, transfer to receiver if needed
            if (receiver != address(this)) {
                uint256 receiverBalanceBefore = stETH.balanceOf(receiver);

                stETH.safeTransfer(receiver, calculatedAmount);

                uint256 receiverBalanceAfter = stETH.balanceOf(receiver);
                // Update calculatedAmount to reflect actual tokens received after transfer
                // (accounts for additional rounding during transfer)
                calculatedAmount = receiverBalanceAfter - receiverBalanceBefore;
            }
        } else if (
            pool == LidoPoolType.wstETH && direction == LidoPoolDirection.Wrap
        ) {
            // wstETH wrapping: stETH -> wstETH
            _transfer(address(this), transferType, stETHAddress, givenAmount);

            if (approvalNeeded) {
                stETH.forceApprove(wstETH, type(uint256).max - 1);
            }
            calculatedAmount = LidoWrappedPool(wstETH).wrap(givenAmount);

            if (receiver != address(this)) {
                IERC20(wstETH).safeTransfer(receiver, calculatedAmount);
            }
        } else if (
            pool == LidoPoolType.wstETH && direction == LidoPoolDirection.Unwrap
        ) {
            // wstETH unwrapping: wstETH -> stETH
            _transfer(address(this), transferType, wstETH, givenAmount);
            calculatedAmount = LidoWrappedPool(wstETH).unwrap(givenAmount);
            if (receiver != address(this)) {
                uint256 receiverBalanceBefore = stETH.balanceOf(receiver);
                stETH.safeTransfer(receiver, calculatedAmount);
                uint256 receiverBalanceAfter = stETH.balanceOf(receiver);
                // Update calculatedAmount to reflect actual tokens received after transfer
                // (accounts for additional rounding during transfer)
                calculatedAmount = receiverBalanceAfter - receiverBalanceBefore;
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
            TransferType transferType,
            LidoPoolType pool,
            LidoPoolDirection direction,
            bool approvalNeeded
        )
    {
        if (data.length != 24) {
            revert LidoExecutor__InvalidDataLength();
        }

        receiver = address(bytes20(data[0:20]));
        transferType = TransferType(uint8(data[20]));
        pool = LidoPoolType(uint8(data[21]));
        direction = LidoPoolDirection(uint8(data[22]));
        approvalNeeded = data[23] != 0;
    }
}
