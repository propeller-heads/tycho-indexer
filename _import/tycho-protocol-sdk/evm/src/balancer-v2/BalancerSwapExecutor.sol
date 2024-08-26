// SPDX-License-Identifier: UNLICENCED
pragma solidity ^0.8.0;

import "../interfaces/ISwapExecutor.sol";

contract BalancerSwapExecutor is ISwapExecutor {
    address private constant vaultAddress =
        0xBA12222222228d8Ba445958a75a0704d566BF2C8;
    bytes32 private constant swapSelector =
        0x52bbbe2900000000000000000000000000000000000000000000000000000000;
    bytes32 private constant maxUint256 =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;

    /**
     * @dev Executes a Balancer swap.
     * @param givenAmount how much of to swap, depending on exactOut either in-
     * or outAmount.
     * @param data the parameters of the swap. This data is roughly the packed
     * encoding of
     *     the struct below:
     *  ```
     *      struct Params {
     *          // the token that the caller is selling
     *          IERC20 tokenIn;
     *
     *          // the token that the caller is receiving in exchange
     *          IERC20 tokenOut;
     *
     *          // the target pool id
     *          bytes32 poolId;
     *
     *          // the receiver of `tokenOut`
     *          address receiver;
     *
     *          // whether we want exactOut semantics
     *          bool exactOut;
     *
     *          // whether we need to approve the pool to spend `tokenIn`
     *          bool tokenApprovalNeeded;
     *
     *      }
     *  ```
     */
    function swap(uint256 givenAmount, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount)
    {
        IERC20 tokenIn;
        IERC20 tokenOut;
        bytes32 poolId;
        address receiver;
        bool exactOut;
        bool tokenApprovalNeeded;
        assembly {
            tokenIn := shr(96, calldataload(data.offset))
            tokenOut := shr(96, calldataload(add(data.offset, 20)))
            poolId := calldataload(add(data.offset, 40))
            let dataLoad := calldataload(add(data.offset, 72))
            receiver := shr(96, dataLoad)
            exactOut := and(shr(88, dataLoad), 0xff)
            tokenApprovalNeeded := and(shr(80, dataLoad), 0xff)

            // Check if token approval is needed and perform the approval
            if tokenApprovalNeeded {
                // Prepare approve call
                let approveCalldata := mload(0x40)
                mstore(
                    approveCalldata,
                    0x095ea7b300000000000000000000000000000000000000000000000000000000
                ) // approve selector
                mstore(add(approveCalldata, 4), vaultAddress) // spender
                mstore(add(approveCalldata, 36), maxUint256) // value
                    // (maxUint256)

                let success :=
                    call(gas(), tokenIn, 0, approveCalldata, 68, 0, 0)
                if iszero(success) {
                    returndatacopy(0, 0, returndatasize())
                    revert(0, returndatasize())
                }
            }

            let ptr := mload(0x40)
            mstore(ptr, swapSelector)
            //limit: as it is always recalculated during the swap, we use the
            // extremums 0 tokenOut or max(uint256) tokenIn.
            let limit := 0
            if exactOut { limit := maxUint256 }
            // as the singleSwap struct contains a bytes, it's considered as
            // dynamic.
            // dynamic values are encoded at the end of the calldata and have a
            // corresponding offset at the beginning
            // we first need to encode the offset of the singleSwap struct
            mstore(add(ptr, 4), 0xe0)
            // fundManagement.sender: is always address(this)
            mstore(add(ptr, 36), address())
            // fundManagement.fromInternalBalance
            mstore(add(ptr, 68), 0)
            // fundManagement.receiver
            mstore(add(ptr, 100), receiver)
            // fundManagement.toInternalBalance
            mstore(add(ptr, 132), 0)
            // limit
            mstore(add(ptr, 164), limit)
            // deadline
            mstore(add(ptr, 196), timestamp())
            // singleSwap.poolId
            mstore(add(ptr, 228), poolId)
            // singleSwap.exactOut
            mstore(add(ptr, 260), exactOut)
            // singleSwap.assetIn
            mstore(add(ptr, 292), tokenIn)
            // singleSwap.assetOut
            mstore(add(ptr, 324), tokenOut)
            // singleSwap.amount
            mstore(add(ptr, 356), givenAmount)
            // singleSwap.userData offset
            mstore(add(ptr, 388), 0xc0)
            // singleSwap.userData lenght
            mstore(add(ptr, 420), 0)

            let success := call(gas(), vaultAddress, 0, ptr, 452, ptr, 32)
            switch success
            case 0 {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
            default { calculatedAmount := mload(ptr) }
        }
    }
}
