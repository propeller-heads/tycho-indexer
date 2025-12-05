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

interface LidoPool {
    // slither-disable-next-line naming-convention
    function submit(address _referral) external payable returns (uint256);
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

    address public immutable st_eth;
    address public immutable wst_eth;

    constructor(
        address _st_eth_address,
        address _wst_eth_address,
        address _permit2
    ) RestrictTransferFrom(_permit2) {
        st_eth = _st_eth_address;
        wst_eth = _wst_eth_address;
    }

    // slither-disable-next-line locked-ether
    function swap(
        uint256 givenAmount,
        bytes calldata data //abi packed encoded
    )
        external
        payable
        returns (uint256 calculatedAmount)
    {
        address receiver;
        TransferType transferType;
        LidoPoolType pool;
        LidoPoolDirection direction;

        (receiver, transferType, pool, direction) = _decodeData(data);

        if (pool == LidoPoolType.stETH && direction == LidoPoolDirection.Stake)
        {
            // stETH staking: ETH -> stETH
            // stETH is a rebasing token where balances are calculated from shares
            // Measure actual balance changes to account for rounding in share conversions
            uint256 balanceBefore = IERC20(st_eth).balanceOf(address(this));

            LidoPool(st_eth).submit{value: givenAmount}(receiver); // TODO: passing receiver here is unnecessary

            uint256 balanceAfter = IERC20(st_eth).balanceOf(address(this));
            calculatedAmount = balanceAfter - balanceBefore;

            // submit() sends stETH to this contract, transfer to receiver if needed
            if (receiver != address(this)) {
                uint256 receiverBalanceBefore =
                    IERC20(st_eth).balanceOf(receiver);

                IERC20(st_eth).safeTransfer(receiver, calculatedAmount);

                uint256 receiverBalanceAfter =
                    IERC20(st_eth).balanceOf(receiver);
                // Update calculatedAmount to reflect actual tokens received after transfer
                // (accounts for additional rounding during transfer)
                calculatedAmount = receiverBalanceAfter - receiverBalanceBefore;
            }
        } else if (
            pool == LidoPoolType.wstETH && direction == LidoPoolDirection.Wrap
        ) {
            //wsteth, steth -> wsteth
            _transfer(address(this), transferType, st_eth, givenAmount);

            if (approvalNeeded) {
                IERC20(st_eth).forceApprove(wst_eth, type(uint256).max -1 );
            }
            calculatedAmount = LidoWrappedPool(wst_eth).wrap(givenAmount);

            if (receiver != address(this)) {
                IERC20(wst_eth).safeTransfer(receiver, calculatedAmount);
            }
        } else if (
            pool == LidoPoolType.wstETH && direction == LidoPoolDirection.Unwrap
        ) {
            //wsteth, wsteth -> steth
            _transfer(address(this), transferType, wst_eth, givenAmount);
            calculatedAmount = LidoWrappedPool(wst_eth).unwrap(givenAmount);
            if (receiver != address(this)) {
                uint256 receiverBalanceBefore =
                    IERC20(st_eth).balanceOf(receiver);
                IERC20(st_eth).safeTransfer(receiver, calculatedAmount);
                uint256 receiverBalanceAfter =
                    IERC20(st_eth).balanceOf(receiver);
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
            LidoPoolDirection direction
        )
    {
        if (data.length != 23) {
            // TODO: double check the length
            revert LidoExecutor__InvalidDataLength();
        }

        receiver = address(bytes20(data[0:20]));
        transferType = TransferType(uint8(data[20]));
        pool = LidoPoolType(uint8(data[21]));
        direction = LidoPoolDirection(uint8(data[22]));
    }
}
