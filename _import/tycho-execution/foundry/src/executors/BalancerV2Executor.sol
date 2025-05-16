// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import {
    IERC20,
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
// slither-disable-next-line solc-version
import {IAsset} from "@balancer-labs/v2-interfaces/contracts/vault/IAsset.sol";
// slither-disable-next-line solc-version
import {IVault} from "@balancer-labs/v2-interfaces/contracts/vault/IVault.sol";
import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";

    error BalancerV2Executor__InvalidDataLength();

contract BalancerV2Executor is IExecutor, RestrictTransferFrom {
    using SafeERC20 for IERC20;

    address private constant VAULT = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;

    constructor(address _permit2) RestrictTransferFrom(_permit2) {}

    // slither-disable-next-line locked-ether
    function swap(uint256 givenAmount, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount)
    {
        (
            IERC20 tokenIn,
            IERC20 tokenOut,
            bytes32 poolId,
            address receiver,
            bool approvalNeeded,
            TransferType transferType
        ) = _decodeData(data);

        _transfer(address(this), transferType, tokenIn, givenAmount);

        if (approvalNeeded) {
            // slither-disable-next-line unused-return
            tokenIn.forceApprove(VAULT, type(uint256).max);
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

        calculatedAmount =
            IVault(VAULT).swap(singleSwap, funds, limit, block.timestamp);
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            IERC20 tokenIn,
            IERC20 tokenOut,
            bytes32 poolId,
            address receiver,
            bool approvalNeeded
        )
    {
        if (data.length != 93) {
            revert BalancerV2Executor__InvalidDataLength();
        }

        tokenIn = IERC20(address(bytes20(data[0:20])));
        tokenOut = IERC20(address(bytes20(data[20:40])));
        poolId = bytes32(data[40:72]);
        receiver = address(bytes20(data[72:92]));
        approvalNeeded = data[92] != 0;
    }
}
