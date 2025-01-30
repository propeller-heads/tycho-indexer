// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@interfaces/IExecutor.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";

error UniswapV3Executor__InvalidDataLength();

contract UniswapV3Executor is IExecutor {
    uint160 private constant MIN_SQRT_RATIO = 4295128739;
    uint160 private constant MAX_SQRT_RATIO =
        1461446703485210103287273052203988822378723970342;
    address private constant factoryV3 =
        0x1F98431c8aD98523631AE4a59f267346ea31F984;

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 amountOut)
    {
        (
            address tokenIn,
            address tokenOut,
            uint24 fee,
            address receiver,
            address target,
            bool zeroForOne
        ) = _decodeData(data);
        int256 amount0;
        int256 amount1;
        IUniswapV3Pool pool = IUniswapV3Pool(target);

        bytes memory callbackData = _makeV3CallbackData(tokenIn, tokenOut, fee);

        {
            (amount0, amount1) = pool.swap(
                receiver,
                zeroForOne,
                // positive means exactIn
                int256(amountIn),
                zeroForOne ? MIN_SQRT_RATIO + 1 : MAX_SQRT_RATIO - 1,
                callbackData
            );
        }

        if (zeroForOne) {
            amountOut = amount1 > 0 ? uint256(amount1) : uint256(-amount1);
        } else {
            amountOut = amount0 > 0 ? uint256(amount0) : uint256(-amount0);
        }
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            address tokenIn,
            address tokenOut,
            uint24 fee,
            address receiver,
            address target,
            bool zeroForOne
        )
    {
        if (data.length != 84) {
            revert UniswapV3Executor__InvalidDataLength();
        }
        tokenIn = address(bytes20(data[0:20]));
        tokenOut = address(bytes20(data[20:40]));
        fee = uint24(bytes3(data[40:43]));
        receiver = address(bytes20(data[43:63]));
        target = address(bytes20(data[63:83]));
        zeroForOne = uint8(data[83]) > 0;
    }

    function _makeV3CallbackData(address tokenIn, address tokenOut, uint24 fee)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(tokenIn, tokenOut, fee);
    }
}
