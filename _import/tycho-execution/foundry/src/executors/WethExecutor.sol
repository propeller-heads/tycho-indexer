// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {
    IERC20,
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";

interface IWETH is IERC20 {
    function deposit() external payable;
    function withdraw(uint256) external;
}

error WethExecutor__InvalidDataLength();
error WethExecutor__SenderIsNotVault(address sender);
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

contract WethExecutor is IExecutor {
    using SafeERC20 for IWETH;
    using SafeERC20 for IERC20;

    IWETH public constant WETH =
        IWETH(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);

    constructor() {}

    function fundsExpectedAddress(
        bytes calldata /* data */
    )
        external
        view
        returns (address receiver)
    {
        return msg.sender;
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data, address receiver)
        external
        payable
        returns (uint256 amountOut, address tokenOut)
    {
        bool isWrapping;
        isWrapping = _decodeData(data);

        if (isWrapping) {
            // ETH -> WETH: Wrap
            WETH.deposit{value: amountIn}();
            amountOut = amountIn;
            tokenOut = address(WETH);

            if (receiver != address(this)) {
                WETH.safeTransfer(receiver, amountOut);
            }
        } else {
            // WETH -> ETH: Unwrap
            WETH.withdraw(amountIn);
            amountOut = amountIn;
            tokenOut = address(0);

            if (receiver != address(this)) {
                Address.sendValue(payable(receiver), amountOut);
            }
        }
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (bool isWrapping)
    {
        if (data.length != 1) {
            revert WethExecutor__InvalidDataLength();
        }

        isWrapping = uint8(data[0]) == 1;
        return isWrapping;
    }

    /// @dev Required to receive ETH
    receive() external payable {}

    function getTransferData(bytes calldata data)
        external
        payable
        returns (
            RestrictTransferFrom.TransferType transferType,
            address receiver,
            address tokenIn
        )
    {
        if (data.length != 1) {
            revert WethExecutor__InvalidDataLength();
        }

        bool isWrapping = uint8(data[0]) == 1;

        if (isWrapping) {
            // ETH -> WETH: Wrap
            tokenIn = address(0);
            transferType =
            RestrictTransferFrom.TransferType.TransferNativeInExecutor;
        } else {
            // WETH -> ETH: Unwrap
            tokenIn = address(WETH);
            transferType = RestrictTransferFrom.TransferType.ProtocolWillDebit;
        }

        receiver = address(this);
    }
}
