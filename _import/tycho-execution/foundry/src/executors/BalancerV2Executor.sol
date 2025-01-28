// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@interfaces/IExecutor.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@balancer-labs/v2-interfaces/contracts/vault/IAsset.sol";
import "@balancer-labs/v2-interfaces/contracts/vault/IVault.sol";


error BalancerV2Executor__InvalidDataLength();

contract BalancerV2Executor is IExecutor {
    using SafeERC20 for IERC20;

    address private constant VAULT = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;

    function swap(uint256 givenAmount, bytes calldata data)
        external
        returns (uint256 calculatedAmount)
    {
        (
            IERC20 tokenIn,
            IERC20 tokenOut,
            bytes32 poolId,
            address receiver,
            bool needsApproval
        ) = _decodeData(data);

        if (needsApproval) {
            tokenIn.safeApprove(VAULT, type(uint256).max);
        }

        IVault.SingleSwap memory singleSwap = IVault.SingleSwap({
            poolId: poolId,
            kind: IVault.SwapKind.GIVEN_IN,
            assetIn: IAsset(address(tokenIn)),
            assetOut: IAsset(address(tokenOut)),
            amount: givenAmount,
            userData: ""
        });

        IVault.FundManagement memory funds = IVault.FundManagement({
            sender: address(this),
            fromInternalBalance: false,
            recipient: payable(receiver),
            toInternalBalance: false
        });

        uint256 limit = 0;

        calculatedAmount = IVault(VAULT).swap(
            singleSwap,
            funds,
            limit,
            block.timestamp
        );
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            IERC20 tokenIn,
            IERC20 tokenOut,
            bytes32 poolId,
            address receiver,
            bool needsApproval
        )
    {
        if (data.length != 93) {
            revert BalancerV2Executor__InvalidDataLength();
        }

        tokenIn = IERC20(address(bytes20(data[0:20])));
        tokenOut = IERC20(address(bytes20(data[20:40])));
        poolId = bytes32(data[40:72]);
        receiver = address(bytes20(data[72:92]));
        needsApproval = uint8(data[92]) > 0;
    }
}