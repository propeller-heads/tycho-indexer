// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {
    SafeERC20,
    IERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {
    IUniswapV3Pool
} from "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";
import {ICallback} from "@interfaces/ICallback.sol";
import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

error UniswapV3Executor__InvalidDataLength();
error UniswapV3Executor__InvalidFactory();
error UniswapV3Executor__InvalidTarget();
error UniswapV3Executor__InvalidInitCode();

contract UniswapV3Executor is IExecutor, ICallback {
    using SafeERC20 for IERC20;

    uint160 private constant MIN_SQRT_RATIO = 4295128739;
    uint160 private constant MAX_SQRT_RATIO =
        1461446703485210103287273052203988822378723970342;

    address public immutable factory;
    bytes32 public immutable initCode;
    address private immutable self;

    constructor(address _factory, bytes32 _initCode) {
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
        returns (uint256 calculatedAmount, address tokenOut, address receiver)
    {
        address tokenIn;
        uint24 fee;
        address target;
        bool zeroForOne;
        RestrictTransferFrom.TransferType transferType;
        (tokenIn, tokenOut, fee, receiver, target, zeroForOne, transferType) =
            _decodeData(data);

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
            calculatedAmount =
                amount1 > 0 ? uint256(amount1) : uint256(-amount1);
        } else {
            calculatedAmount =
                amount0 > 0 ? uint256(amount0) : uint256(-amount0);
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
        uint24 poolFee = uint24(bytes3(data[40:43]));

        _verifyPairAddress(tokenIn, tokenOut, poolFee, msg.sender);
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
            RestrictTransferFrom.TransferType transferType
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
        transferType = RestrictTransferFrom.TransferType(uint8(data[84]));
    }

    function _makeV3CallbackData(
        address tokenIn,
        address tokenOut,
        uint24 fee,
        RestrictTransferFrom.TransferType transferType
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

    function getTransferData(
        bytes calldata /* data */
    )
        external
        payable
        returns (
            RestrictTransferFrom.TransferType transferType,
            address receiver,
            address tokenIn
        )
    {
        return (RestrictTransferFrom.TransferType.None, address(0), address(0));
    }

    function getCallbackTransferData(bytes calldata data)
        external
        payable
        returns (
            RestrictTransferFrom.TransferType transferType,
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
        transferType = RestrictTransferFrom.TransferType(uint8(data[175]));
        receiver = msg.sender;
    }
}
