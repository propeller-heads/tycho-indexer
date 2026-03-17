pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {
    SafeERC20,
    IERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ICallback} from "@interfaces/ICallback.sol";
import {
    IUniswapV3Pool
} from "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";
import {TransferManager} from "../TransferManager.sol";

error SlipstreamsExecutor__InvalidDataLength();

contract SlipstreamsExecutor is IExecutor, ICallback {
    using SafeERC20 for IERC20;

    uint160 private constant _MIN_SQRT_RATIO = 4295128739;
    uint160 private constant _MAX_SQRT_RATIO =
        1461446703485210103287273052203988822378723970342;

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
    {
        address tokenIn;
        address tokenOut;
        int24 tickSpacing;
        address target;
        bool zeroForOne;
        (tokenIn, tokenOut, tickSpacing, target, zeroForOne) = _decodeData(data);

        IUniswapV3Pool pool = IUniswapV3Pool(target);

        bytes memory callbackData = data[0:43];

        // slither-disable-next-line unused-return
        pool.swap(
            receiver,
            zeroForOne,
            // positive means exactIn
            int256(amountIn),
            zeroForOne ? _MIN_SQRT_RATIO + 1 : _MAX_SQRT_RATIO - 1,
            callbackData
        );
    }

    function handleCallback(bytes calldata msgData)
        public
        pure
        returns (bytes memory result)
    {
        // The data has the following layout:
        // - selector (4 bytes)
        // - amount0Delta (32 bytes)
        // - amount1Delta (32 bytes)
        // - dataOffset (32 bytes)
        // - dataLength (32 bytes)
        // - protocolData (variable length)

        (int256 amount0Delta, int256 amount1Delta) =
            abi.decode(msgData[4:68], (int256, int256));

        address tokenIn = address(bytes20(msgData[132:152]));

        uint256 amountOwed =
            amount0Delta > 0 ? uint256(amount0Delta) : uint256(amount1Delta);

        return abi.encode(amountOwed, tokenIn);
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            address tokenIn,
            address tokenOut,
            int24 tickSpacing,
            address target,
            bool zeroForOne
        )
    {
        if (data.length != 64) {
            revert SlipstreamsExecutor__InvalidDataLength();
        }
        tokenIn = address(bytes20(data[0:20]));
        tokenOut = address(bytes20(data[20:40]));
        tickSpacing = int24(uint24(bytes3(data[40:43])));
        target = address(bytes20(data[43:63]));
        zeroForOne = uint8(data[63]) > 0;
    }

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
        if (data.length >= 40) {
            tokenIn = address(bytes20(data[0:20]));
            tokenOut = address(bytes20(data[20:40]));
        }
        return (
            TransferManager.TransferType.None,
            address(0),
            tokenIn,
            tokenOut,
            false
        );
    }

    function getCallbackTransferData(bytes calldata data)
        external
        payable
        returns (
            TransferManager.TransferType transferType,
            address receiver,
            address tokenIn,
            uint256 amount
        )
    {
        (int256 amount0Delta, int256 amount1Delta) =
            abi.decode(data[4:68], (int256, int256));
        amount =
            amount0Delta > 0 ? uint256(amount0Delta) : uint256(amount1Delta);
        tokenIn = address(bytes20(data[132:152]));
        transferType = TransferManager.TransferType.Transfer;
        receiver = msg.sender;
    }
}
