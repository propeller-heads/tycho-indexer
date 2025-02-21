// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";
import "@uniswap/v3-updated/CallbackValidationV2.sol";
import "@interfaces/ICallback.sol";

error UniswapV3Executor__InvalidDataLength();
error UniswapV3Executor__InvalidFactory();
error UniswapV3Executor__InvalidTarget();

contract UniswapV3Executor is IExecutor, ICallback {
    using SafeERC20 for IERC20;

    uint160 private constant MIN_SQRT_RATIO = 4295128739;
    uint160 private constant MAX_SQRT_RATIO =
        1461446703485210103287273052203988822378723970342;

    address public immutable factory;
    address private immutable self;

    constructor(address _factory) {
        if (_factory == address(0)) {
            revert UniswapV3Executor__InvalidFactory();
        }
        factory = _factory;
        self = address(this);
    }

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

        if (target != _computePairAddress(tokenIn, tokenOut, fee)) {
            revert UniswapV3Executor__InvalidTarget();
        }

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

    function handleCallback(bytes calldata msgData)
        public
        returns (bytes memory result)
    {
        // The data has the following layout:
        // - amount0Delta (32 bytes)
        // - amount1Delta (32 bytes)
        // - dataOffset (32 bytes)
        // - dataLength (32 bytes)
        // - protocolData (variable length)

        (int256 amount0Delta, int256 amount1Delta) =
            abi.decode(msgData[:64], (int256, int256));

        address tokenIn = address(bytes20(msgData[128:148]));

        verifyCallback(msgData[128:]);

        uint256 amountOwed =
            amount0Delta > 0 ? uint256(amount0Delta) : uint256(amount1Delta);

        IERC20(tokenIn).safeTransfer(msg.sender, amountOwed);
        return abi.encode(amountOwed, tokenIn);
    }

    function verifyCallback(bytes calldata data) public view {
        address tokenIn = address(bytes20(data[0:20]));
        address tokenOut = address(bytes20(data[20:40]));
        uint24 poolFee = uint24(bytes3(data[40:43]));

        // slither-disable-next-line unused-return
        CallbackValidationV2.verifyCallback(factory, tokenIn, tokenOut, poolFee);
    }

    function uniswapV3SwapCallback(
        int256, /* amount0Delta */
        int256, /* amount1Delta */
        bytes calldata /* data */
    ) external {
        uint256 dataOffset = 4 + 32 + 32 + 32; // Skip selector + 2 ints + data_offset
        uint256 dataLength =
            uint256(bytes32(msg.data[dataOffset:dataOffset + 32]));

        bytes calldata fullData = msg.data[4:dataOffset + 32 + dataLength];

        handleCallback(fullData);
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
        view
        returns (bytes memory)
    {
        return abi.encodePacked(
            tokenIn, tokenOut, fee, self, ICallback.handleCallback.selector
        );
    }

    function _computePairAddress(address tokenA, address tokenB, uint24 fee)
        internal
        view
        returns (address pool)
    {
        (address token0, address token1) =
            tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        pool = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            hex"ff",
                            factory,
                            keccak256(abi.encode(token0, token1, fee)),
                            hex"e34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54"
                        )
                    )
                )
            )
        );
    }
}
