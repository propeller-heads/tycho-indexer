// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";
import "@interfaces/ICallback.sol";
import "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";
import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";
import "@openzeppelin/contracts/utils/Address.sol";

error SlipstreamsExecutor__InvalidDataLength();
error SlipstreamsExecutor__InvalidFactory();
error SlipstreamsExecutor__InvalidTarget();

interface ICLFactory {
    function poolImplementation() external view returns (address);
}

contract SlipstreamsExecutor is IExecutor, ICallback, RestrictTransferFrom {
    using SafeERC20 for IERC20;

    uint160 private constant MIN_SQRT_RATIO = 4295128739;
    uint160 private constant MAX_SQRT_RATIO =
        1461446703485210103287273052203988822378723970342;

    address public immutable factory;
    address private immutable self;

    /// @notice The identifying key of the pool
    struct PoolKey {
        address token0;
        address token1;
        int24 tickSpacing;
    }

    constructor(address _factory, address _permit2)
        RestrictTransferFrom(_permit2)
    {
        if (_factory == address(0)) {
            revert SlipstreamsExecutor__InvalidFactory();
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
            int24 tick_spacing,,
            address receiver,
            address target,
            bool zeroForOne
        ) = _decodeData(data);

        _verifyPairAddress(tokenIn, tokenOut, tick_spacing, target);

        int256 amount0;
        int256 amount1;
        IUniswapV3Pool pool = IUniswapV3Pool(target);

        bytes memory callbackData = data[0:44];

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
        int24 tickSpacing = int24(uint24(bytes3(data[40:43])));
        _verifyPairAddress(tokenIn, tokenOut, tickSpacing, msg.sender);
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
            int24 tick_spacing,
            TransferType transferType,
            address receiver,
            address target,
            bool zeroForOne
        )
    {
        if (data.length != 85) {
            revert SlipstreamsExecutor__InvalidDataLength();
        }
        tokenIn = address(bytes20(data[0:20]));
        tokenOut = address(bytes20(data[20:40]));
        tick_spacing = int24(uint24(bytes3(data[40:43])));
        transferType = TransferType(uint8(data[43]));
        receiver = address(bytes20(data[44:64]));
        target = address(bytes20(data[64:84]));
        zeroForOne = uint8(data[84]) > 0;
    }

    function getPoolKey(address tokenA, address tokenB, int24 tickSpacing)
        internal
        pure
        returns (PoolKey memory)
    {
        if (tokenA > tokenB) (tokenA, tokenB) = (tokenB, tokenA);
        return
            PoolKey({token0: tokenA, token1: tokenB, tickSpacing: tickSpacing});
    }

    function computeAddress(PoolKey memory key)
        internal
        view
        returns (address pool)
    {
        require(key.token0 < key.token1);
        pool = Clones.predictDeterministicAddress(
            ICLFactory(factory).poolImplementation(),
            keccak256(abi.encode(key.token0, key.token1, key.tickSpacing)),
            factory
        );
    }

    function _verifyPairAddress(
        address tokenA,
        address tokenB,
        int24 tick_spacing,
        address target
    ) internal view {
        address pool = computeAddress(getPoolKey(tokenA, tokenB, tick_spacing));
        if (pool != target) {
            revert SlipstreamsExecutor__InvalidTarget();
        }
    }
}
