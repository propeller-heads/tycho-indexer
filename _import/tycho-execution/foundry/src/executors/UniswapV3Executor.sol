// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";
import "@interfaces/ICallback.sol";
import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";
import "@openzeppelin/contracts/utils/Address.sol";

error UniswapV3Executor__InvalidDataLength();
error UniswapV3Executor__InvalidFactory();
error UniswapV3Executor__InvalidTarget();
error UniswapV3Executor__InvalidInitCode();

contract UniswapV3Executor is IExecutor, ICallback, RestrictTransferFrom {
    using SafeERC20 for IERC20;

    uint160 private constant MIN_SQRT_RATIO = 4295128739;
    uint160 private constant MAX_SQRT_RATIO =
        1461446703485210103287273052203988822378723970342;

    address public immutable factory;
    bytes32 public immutable initCode;
    address private immutable self;

    constructor(address _factory, bytes32 _initCode, address _permit2)
        RestrictTransferFrom(_permit2)
    {
        if (_factory == address(0)) {
            revert UniswapV3Executor__InvalidFactory();
        }
        if (_initCode == bytes32(0)) {
            revert UniswapV3Executor__InvalidInitCode();
        }
        factory = _factory;
        initCode = _initCode;
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
            bool zeroForOne,
            TransferType transferType
        ) = _decodeData(data);

        _verifyPairAddress(tokenIn, tokenOut, fee, target);

        int256 amount0;
        int256 amount1;
        IUniswapV3Pool pool = IUniswapV3Pool(target);

        bytes memory callbackData =
            _makeV3CallbackData(tokenIn, tokenOut, fee, transferType);

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
        // - selector (4 bytes)
        // - amount0Delta (32 bytes)
        // - amount1Delta (32 bytes)
        // - dataOffset (32 bytes)
        // - dataLength (32 bytes)
        // - protocolData (variable length)

        (int256 amount0Delta, int256 amount1Delta) =
            abi.decode(msgData[4:68], (int256, int256));

        address tokenIn = address(bytes20(msgData[132:152]));
        TransferType transferType = TransferType(uint8(msgData[175]));

        verifyCallback(msgData[132:]);

        uint256 amountOwed =
            amount0Delta > 0 ? uint256(amount0Delta) : uint256(amount1Delta);

        _transfer(msg.sender, transferType, tokenIn, amountOwed);

        return abi.encode(amountOwed, tokenIn);
    }

    function verifyCallback(bytes calldata data) public view {
        address tokenIn = address(bytes20(data[0:20]));
        address tokenOut = address(bytes20(data[20:40]));
        uint24 poolFee = uint24(bytes3(data[40:43]));

        _verifyPairAddress(tokenIn, tokenOut, poolFee, msg.sender);
    }

    function uniswapV3SwapCallback(
        int256, /* amount0Delta */
        int256, /* amount1Delta */
        bytes calldata /* data */
    )
        external
    {
        handleCallback(msg.data);
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
            bool zeroForOne,
            TransferType transferType
        )
    {
        if (data.length != 85) {
            revert UniswapV3Executor__InvalidDataLength();
        }
        tokenIn = address(bytes20(data[0:20]));
        tokenOut = address(bytes20(data[20:40]));
        fee = uint24(bytes3(data[40:43]));
        receiver = address(bytes20(data[43:63]));
        target = address(bytes20(data[63:83]));
        zeroForOne = uint8(data[83]) > 0;
        transferType = TransferType(uint8(data[84]));
    }

    function _makeV3CallbackData(
        address tokenIn,
        address tokenOut,
        uint24 fee,
        TransferType transferType
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(tokenIn, tokenOut, fee, uint8(transferType));
    }

    function _verifyPairAddress(
        address tokenA,
        address tokenB,
        uint24 fee,
        address target
    ) internal view {
        (address token0, address token1) =
            tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        address pool = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            hex"ff",
                            factory,
                            keccak256(abi.encode(token0, token1, fee)),
                            initCode
                        )
                    )
                )
            )
        );
        if (pool != target) {
            revert UniswapV3Executor__InvalidTarget();
        }
    }
}
