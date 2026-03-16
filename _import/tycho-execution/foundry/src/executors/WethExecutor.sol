pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {
    IERC20,
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {TransferManager} from "../TransferManager.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

interface IWETH is IERC20 {
    function deposit() external payable;
    function withdraw(uint256) external;
}

error WethExecutor__InvalidDataLength();
error WethExecutor__ZeroAddres();

contract WethExecutor is IExecutor {
    using SafeERC20 for IWETH;
    using SafeERC20 for IERC20;

    IWETH public immutable weth;

    constructor(address wethAddress) {
        if (wethAddress == address(0)) {
            revert WethExecutor__ZeroAddres();
        }
        weth = IWETH(wethAddress);
    }

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
            weth.deposit{value: amountIn}();
            amountOut = amountIn;
            tokenOut = address(weth);

            if (receiver != address(this)) {
                weth.safeTransfer(receiver, amountOut);
            }
        } else {
            // WETH -> ETH: Unwrap
            weth.withdraw(amountIn);
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
            TransferManager.TransferType transferType,
            address receiver,
            address tokenIn,
            address tokenOut,
            bool outputToRouter
        )
    {
        if (data.length != 1) {
            revert WethExecutor__InvalidDataLength();
        }

        bool isWrapping = uint8(data[0]) == 1;

        if (isWrapping) {
            // ETH -> WETH: Wrap
            tokenIn = address(0);
            tokenOut = address(weth);
            transferType = TransferManager.TransferType.TransferNativeInExecutor;
        } else {
            // WETH -> ETH: Unwrap
            tokenIn = address(weth);
            tokenOut = address(0);
            transferType = TransferManager.TransferType.ProtocolWillDebit;
        }

        outputToRouter = true;
        // Since unwrapping withdraws the funds from the msg.sender, the user's funds need to be sent to the
        // TychoRouter initially. This does not require an actual approval since our
        // router is interacting directly with the token contract.
        // We use msg.sender (the TychoRouter) instead of address(this) because
        // getTransferData is called via staticcall.
        receiver = msg.sender;
    }
}
