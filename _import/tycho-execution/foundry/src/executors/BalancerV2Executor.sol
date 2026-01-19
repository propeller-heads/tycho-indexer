// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
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

contract BalancerV2Executor is IExecutor {
    using SafeERC20 for IERC20;

    address private constant VAULT = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;

    constructor() {}

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 amountOut, address tokenOut, address receiver)
    {
        address tokenIn;
        bytes32 poolId;
        bool approvalNeeded;

        (tokenIn, tokenOut, poolId, receiver, approvalNeeded) =
            _decodeData(data);

        IVault.SingleSwap memory singleSwap = IVault.SingleSwap({
            poolId: poolId,
            kind: IVault.SwapKind.GIVEN_IN,
            assetIn: IAsset(address(tokenIn)),
            assetOut: IAsset(address(tokenOut)),
            amount: amountIn,
            userData: ""
        });

        IVault.FundManagement memory funds = IVault.FundManagement({
            sender: address(this),
            fromInternalBalance: false,
            recipient: payable(receiver),
            toInternalBalance: false
        });

        uint256 limit = 0;

        amountOut =
            IVault(VAULT).swap(singleSwap, funds, limit, block.timestamp);
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            address tokenIn,
            address tokenOut,
            bytes32 poolId,
            address receiver,
            bool approvalNeeded
        )
    {
        if (data.length != 94) {
            revert BalancerV2Executor__InvalidDataLength();
        }

        tokenIn = address(bytes20(data[0:20]));
        tokenOut = address(bytes20(data[20:40]));
        poolId = bytes32(data[40:72]);
        receiver = address(bytes20(data[72:92]));
        approvalNeeded = data[92] != 0;
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
        if (data.length != 94) {
            revert BalancerV2Executor__InvalidDataLength();
        }

        tokenIn = address(bytes20(data[0:20]));
        // The receiver of the funds will be the Balancer Vault.
        // This protocol will only ever have the following transferTypes:
        // - TransferFromAndProtocolWillDebit: the funds should be transferred to the TychoRouter and the Balancer Vault needs to be approved
        // - ProtocolWillDebit: Balancer Vault needs to be approved
        receiver = VAULT;
        transferType = RestrictTransferFrom.TransferType(uint8(data[93]));
    }
}
