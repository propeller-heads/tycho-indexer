// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
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
import {ICallback} from "../../interfaces/ICallback.sol";

error BalancerV3Executor__InvalidDataLength();
error BalancerV3Executor__SenderIsNotVault(address sender);

contract BalancerV3Executor is IExecutor, RestrictTransferFrom, ICallback {
    using SafeERC20 for IERC20;

    IVault private constant VAULT =
        IVault(0xbA1333333333a1BA1108E8412f11850A5C319bA9);

    constructor(address _permit2) RestrictTransferFrom(_permit2) {}

    // slither-disable-next-line locked-ether
    function swap(uint256 givenAmount, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount)
    {
        bytes memory result = VAULT.unlock(
            abi.encodeCall(
                BalancerV3Executor.handleCallback,
                abi.encodePacked(givenAmount, data)
            )
        );
        calculatedAmount = abi.decode(abi.decode(result, (bytes)), (uint256));
    }

    function verifyCallback(bytes calldata /*data*/ ) public view {
        if (msg.sender != address(VAULT)) {
            revert BalancerV3Executor__SenderIsNotVault(msg.sender);
        }
    }

    function handleCallback(bytes calldata data)
        external
        returns (bytes memory result)
    {
        verifyCallback(data);
        (
            uint256 amountGiven,
            IERC20 tokenIn,
            IERC20 tokenOut,
            address poolId,
            TransferType transferType,
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

        _transfer(address(VAULT), transferType, address(tokenIn), amountIn);
        // slither-disable-next-line unused-return
        VAULT.settle(tokenIn, amountIn);
        VAULT.sendTo(tokenOut, receiver, amountOut);
        return abi.encode(amountCalculated);
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            uint256 amountGiven,
            IERC20 tokenIn,
            IERC20 tokenOut,
            address poolId,
            TransferType transferType,
            address receiver
        )
    {
        if (data.length != 113) {
            revert BalancerV3Executor__InvalidDataLength();
        }

        amountGiven = uint256(bytes32(data[0:32]));
        tokenIn = IERC20(address(bytes20(data[32:52])));
        tokenOut = IERC20(address(bytes20(data[52:72])));
        poolId = address(bytes20(data[72:92]));
        transferType = TransferType(uint8(data[92]));
        receiver = address(bytes20(data[93:113]));
    }
}
