// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {
    SafeERC20,
    IERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {ICallback} from "@interfaces/ICallback.sol";
import {
    IUniswapV3Pool
} from "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";
import {TransferManager} from "../TransferManager.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

error SlipstreamsExecutor__InvalidDataLength();
error SlipstreamsExecutor__InvalidFactory();
error SlipstreamsExecutor__InvalidTarget();

interface ICLFactory {
    function poolImplementation() external view returns (address);
}

contract SlipstreamsExecutor is IExecutor, ICallback {
    using SafeERC20 for IERC20;

    uint160 private constant _MIN_SQRT_RATIO = 4295128739;
    uint160 private constant _MAX_SQRT_RATIO =
        1461446703485210103287273052203988822378723970342;

    address public immutable factory1;
    address public immutable factory2;
    address private immutable _self;

    /// @notice The identifying key of the pool
    struct PoolKey {
        address token0;
        address token1;
        int24 tickSpacing;
    }

    constructor(address factory1_, address factory2_) {
        if (factory1_ == address(0) || factory2_ == address(0)) {
            revert SlipstreamsExecutor__InvalidFactory();
        }
        factory1 = factory1_;
        factory2 = factory2_;
        _self = address(this);
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
        address tokenIn;
        int24 tickSpacing;
        address target;
        bool zeroForOne;
        (tokenIn, tokenOut, tickSpacing, target, zeroForOne) = _decodeData(data);

        _verifyPairAddress(tokenIn, tokenOut, tickSpacing, target);

        int256 amount0;
        int256 amount1;
        IUniswapV3Pool pool = IUniswapV3Pool(target);

        bytes memory callbackData = data[0:43];

        {
            (amount0, amount1) = pool.swap(
                receiver,
                zeroForOne,
                // positive means exactIn
                int256(amountIn),
                zeroForOne ? _MIN_SQRT_RATIO + 1 : _MAX_SQRT_RATIO - 1,
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
        view
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

        verifyCallback(msgData[132:]);

        uint256 amountOwed =
            amount0Delta > 0 ? uint256(amount0Delta) : uint256(amount1Delta);

        return abi.encode(amountOwed, tokenIn);
    }

    function verifyCallback(bytes calldata data) public view {
        address tokenIn = address(bytes20(data[0:20]));
        address tokenOut = address(bytes20(data[20:40]));
        int24 tickSpacing = int24(uint24(bytes3(data[40:43])));
        _verifyPairAddress(tokenIn, tokenOut, tickSpacing, msg.sender);
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

    function getPoolKey(address tokenA, address tokenB, int24 tickSpacing)
        internal
        pure
        returns (PoolKey memory)
    {
        if (tokenA > tokenB) (tokenA, tokenB) = (tokenB, tokenA);
        return
            PoolKey({token0: tokenA, token1: tokenB, tickSpacing: tickSpacing});
    }

    function computeAddress(PoolKey memory key, address factory)
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
        int24 tickSpacing,
        address target
    ) internal view {
        PoolKey memory key = getPoolKey(tokenA, tokenB, tickSpacing);
        address pool1 = computeAddress(key, factory1);
        address pool2 = computeAddress(key, factory2);
        if (pool1 != target && pool2 != target) {
            revert SlipstreamsExecutor__InvalidTarget();
        }
    }

    function getTransferData(
        bytes calldata /* data */
    )
        external
        payable
        returns (
            TransferManager.TransferType transferType,
            address receiver,
            address tokenIn
        )
    {
        return (TransferManager.TransferType.None, address(0), address(0));
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
