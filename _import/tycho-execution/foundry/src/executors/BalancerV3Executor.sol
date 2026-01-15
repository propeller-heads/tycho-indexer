// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {
    IERC20,
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IVault} from "@balancer-labs/v3-interfaces/contracts/vault/IVault.sol";
import {
    SwapKind,
    VaultSwapParams
} from "@balancer-labs/v3-interfaces/contracts/vault/VaultTypes.sol";
import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";
import {ICallback} from "@interfaces/ICallback.sol";

error BalancerV3Executor__InvalidDataLength();
error BalancerV3Executor__SenderIsNotVault(address sender);

contract BalancerV3Executor is IExecutor, ICallback {
    using SafeERC20 for IERC20;

    IVault private constant VAULT =
        IVault(0xbA1333333333a1BA1108E8412f11850A5C319bA9);

    constructor() {}

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount, address tokenOut, address receiver)
    {
        if (data.length != 81) {
            revert BalancerV3Executor__InvalidDataLength();
        }
        bytes memory result = VAULT.unlock(abi.encodePacked(amountIn, data));
        (calculatedAmount, tokenOut, receiver) = abi.decode(
            abi.decode(result, (bytes)), (uint256, address, address)
        );
    }

    function verifyCallback(
        bytes calldata /*data*/
    )
        public
        view
    {
        if (msg.sender != address(VAULT)) {
            revert BalancerV3Executor__SenderIsNotVault(msg.sender);
        }
    }

    function _swapCallback(bytes calldata data)
        internal
        returns (bytes memory result)
    {
        verifyCallback(data);
        (
            uint256 amountGiven,
            IERC20 tokenIn,
            IERC20 tokenOut,
            address poolId,
            address receiver
        ) = _decodeData(data);

        uint256 amountCalculated;
        uint256 amountIn;
        uint256 amountOut;
        (amountCalculated, amountIn, amountOut) = VAULT.swap(
            VaultSwapParams({
                kind: SwapKind.EXACT_IN,
                pool: poolId,
                tokenIn: tokenIn,
                tokenOut: tokenOut,
                amountGivenRaw: amountGiven,
                limitRaw: 0,
                userData: ""
            })
        );

        // slither-disable-next-line unused-return
        VAULT.settle(tokenIn, amountIn);
        VAULT.sendTo(tokenOut, receiver, amountOut);
        return abi.encode(amountCalculated, tokenOut, receiver);
    }

    function handleCallback(bytes calldata data)
        external
        returns (bytes memory result)
    {
        verifyCallback(data);
        result = _swapCallback(data);
        // Our general callback logic returns a not ABI encoded result (see Dispatcher._callHandleCallbackOnExecutor).
        // However, the Vault expects the result to be ABI encoded. That is why we need to encode it here again.
        return abi.encode(result);
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            uint256 amountGiven,
            IERC20 tokenIn,
            IERC20 tokenOut,
            address poolId,
            address receiver
        )
    {
        amountGiven = uint256(bytes32(data[0:32]));
        tokenIn = IERC20(address(bytes20(data[32:52])));
        tokenOut = IERC20(address(bytes20(data[52:72])));
        poolId = address(bytes20(data[72:92]));
        receiver = address(bytes20(data[93:113]));
    }

    function getTransferData(
        bytes calldata /* data */
    )
        external
        payable
        returns (
            RestrictTransferFrom.TransferType transferType,
            address receiver,
            address tokenIn
        )
    {
        return (RestrictTransferFrom.TransferType.None, address(0), address(0));
    }

    function getCallbackTransferData(bytes calldata data)
        external
        payable
        returns (
            RestrictTransferFrom.TransferType transferType,
            address receiver,
            address tokenIn,
            uint256 amount
        )
    {
        receiver = address(VAULT);
        amount = uint256(bytes32(data[0:32]));
        tokenIn = address(bytes20(data[32:52]));
        transferType = RestrictTransferFrom.TransferType(uint8(data[92]));
    }
}
