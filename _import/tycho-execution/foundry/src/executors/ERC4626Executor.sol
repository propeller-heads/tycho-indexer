// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/interfaces/IERC4626.sol";
import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";

error ERC4626Executor__InvalidDataLength();
error ERC4626Executor__InvalidTarget();

contract ERC4626Executor is IExecutor, RestrictTransferFrom {
    using SafeERC20 for IERC20;

    constructor(address _permit2) RestrictTransferFrom(_permit2) {}

    // slither-disable-next-line locked-ether
    function swap(uint256 givenAmount, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount)
    {
        address target;
        address receiver;
        IERC20 tokenIn;
        TransferType transferType;

        (tokenIn, target, receiver, transferType) = _decodeData(data);
        _transfer(address(this), transferType, address(tokenIn), givenAmount);

        if (address(tokenIn) == target) {
            // shares --> asset
            calculatedAmount =
                IERC4626(target).redeem(givenAmount, receiver, address(this));
        } else if (address(tokenIn) == IERC4626(target).asset()) {
            // asset --> shares
            tokenIn.forceApprove(target, type(uint256).max);
            calculatedAmount = IERC4626(target).deposit(givenAmount, receiver);
        } else {
            revert ERC4626Executor__InvalidTarget();
        }
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            IERC20 inToken,
            address target,
            address receiver,
            TransferType transferType
        )
    {
        if (data.length != 61) {
            revert ERC4626Executor__InvalidDataLength();
        }
        inToken = IERC20(address(bytes20(data[0:20])));
        target = address(bytes20(data[20:40]));
        receiver = address(bytes20(data[40:60]));
        transferType = TransferType(uint8(data[60]));
    }
}
