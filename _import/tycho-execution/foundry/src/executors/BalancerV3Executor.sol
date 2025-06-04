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

error BalancerV3Executor__InvalidDataLength();
error BalancerV3Executor__SenderIsNotVault(address sender);

contract BalancerV3Executor is IExecutor, RestrictTransferFrom {
    using SafeERC20 for IERC20;

    IVault private constant VAULT =
        IVault(0xbA1333333333a1BA1108E8412f11850A5C319bA9);

    /**
     * @notice Data for the swap hook.
     * @param pool Address of the liquidity pool
     * @param tokenIn Token to be swapped from
     * @param tokenOut Token to be swapped to
     * @param amountGiven Amount given based on kind of the swap
     * @param transferType Type of transfer to be used for the token in
     * @param receiver Address to receive the output token
     */
    struct SwapHookParams {
        address pool;
        IERC20 tokenIn;
        IERC20 tokenOut;
        uint256 amountGiven;
        TransferType transferType;
        address receiver;
    }

    constructor(address _permit2) RestrictTransferFrom(_permit2) {}

    modifier onlyVault() {
        if (msg.sender != address(VAULT)) {
            revert BalancerV3Executor__SenderIsNotVault(msg.sender);
        }
        _;
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 givenAmount, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount)
    {
        (
            IERC20 tokenIn,
            IERC20 tokenOut,
            address poolId,
            TransferType transferType,
            address receiver
        ) = _decodeData(data);

        calculatedAmount = abi.decode(
            VAULT.unlock(
                abi.encodeCall(
                    BalancerV3Executor.swapHook,
                    SwapHookParams({
                        pool: poolId,
                        tokenIn: tokenIn,
                        tokenOut: tokenOut,
                        amountGiven: givenAmount,
                        transferType: transferType,
                        receiver: receiver
                    })
                )
            ),
            (uint256)
        );
    }

    /**
     * @notice Hook to be called by the Balancer Vault.
     * @param params Parameters for the swap hook.
     * @return amountCalculated The amount calculated after the swap.
     */
    function swapHook(SwapHookParams calldata params)
        external
        onlyVault
        returns (uint256 amountCalculated)
    {
        uint256 amountIn;
        uint256 amountOut;
        (amountCalculated, amountIn, amountOut) = VAULT.swap(
            VaultSwapParams({
                kind: SwapKind.EXACT_IN,
                pool: params.pool,
                tokenIn: params.tokenIn,
                tokenOut: params.tokenOut,
                amountGivenRaw: params.amountGiven,
                limitRaw: 0,
                userData: ""
            })
        );

        _transfer(
            address(VAULT),
            params.transferType,
            address(params.tokenIn),
            amountIn
        );
        // slither-disable-next-line unused-return
        VAULT.settle(params.tokenIn, amountIn);
        VAULT.sendTo(params.tokenOut, params.receiver, amountOut);

        return amountCalculated;
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            IERC20 tokenIn,
            IERC20 tokenOut,
            address poolId,
            TransferType transferType,
            address receiver
        )
    {
        if (data.length != 81) {
            revert BalancerV3Executor__InvalidDataLength();
        }

        tokenIn = IERC20(address(bytes20(data[0:20])));
        tokenOut = IERC20(address(bytes20(data[20:40])));
        poolId = address(bytes20(data[40:60]));
        transferType = TransferType(uint8(data[60]));
        receiver = address(bytes20(data[61:81]));
    }
}
