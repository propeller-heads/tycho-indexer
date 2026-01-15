// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {
    SafeERC20,
    IERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {
    IUniswapV2Pair
} from "@uniswap-v2/contracts/interfaces/IUniswapV2Pair.sol";
import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";

error UniswapV2Executor__InvalidDataLength();
error UniswapV2Executor__InvalidTarget();
error UniswapV2Executor__InvalidFactory();
error UniswapV2Executor__InvalidInitCode();
error UniswapV2Executor__InvalidFee();

contract UniswapV2Executor is IExecutor {
    using SafeERC20 for IERC20;

    address public immutable FACTORY;
    bytes32 public immutable INIT_CODE;
    address private immutable SELF;
    uint256 public immutable FEE_BPS;

    constructor(address _factory, bytes32 _initCode, uint256 _feeBps) {
        if (_factory == address(0)) {
            revert UniswapV2Executor__InvalidFactory();
        }
        if (_initCode == bytes32(0)) {
            revert UniswapV2Executor__InvalidInitCode();
        }
        FACTORY = _factory;
        INIT_CODE = _initCode;
        if (_feeBps > 30) {
            revert UniswapV2Executor__InvalidFee();
        }
        FEE_BPS = _feeBps;
        SELF = address(this);
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount, address tokenOut, address receiver)
    {
        address target;
        bool zeroForOne;

        (target, tokenOut, receiver, zeroForOne) = _decodeData(data);

        _verifyPairAddress(target);

        calculatedAmount = _getAmountOut(target, amountIn, zeroForOne);

        IUniswapV2Pair pool = IUniswapV2Pair(target);
        if (zeroForOne) {
            pool.swap(0, calculatedAmount, receiver, "");
        } else {
            pool.swap(calculatedAmount, 0, receiver, "");
        }
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            address target,
            address tokenOut,
            address receiver,
            bool zeroForOne
        )
    {
        if (data.length != 82) {
            revert UniswapV2Executor__InvalidDataLength();
        }
        target = address(bytes20(data[20:40]));
        tokenOut = address(bytes20(data[40:60]));
        receiver = address(bytes20(data[60:80]));
        zeroForOne = data[80] != 0;
    }

    function _getAmountOut(address target, uint256 amountIn, bool zeroForOne)
        internal
        view
        returns (uint256 amount)
    {
        IUniswapV2Pair pair = IUniswapV2Pair(target);
        uint112 reserveIn;
        uint112 reserveOut;
        if (zeroForOne) {
            // slither-disable-next-line unused-return
            (reserveIn, reserveOut,) = pair.getReserves();
        } else {
            // slither-disable-next-line unused-return
            (reserveOut, reserveIn,) = pair.getReserves();
        }

        require(reserveIn > 0 && reserveOut > 0, "L");
        uint256 amountInWithFee = amountIn * (10000 - FEE_BPS);
        uint256 numerator = amountInWithFee * uint256(reserveOut);
        uint256 denominator = (uint256(reserveIn) * 10000) + amountInWithFee;
        amount = numerator / denominator;
    }

    function _verifyPairAddress(address target) internal view {
        address token0 = IUniswapV2Pair(target).token0();
        address token1 = IUniswapV2Pair(target).token1();
        bytes32 salt = keccak256(abi.encodePacked(token0, token1));
        address pair = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(hex"ff", FACTORY, salt, INIT_CODE)
                    )
                )
            )
        );
        if (pair != target) {
            revert UniswapV2Executor__InvalidTarget();
        }
    }

    function getTransferData(bytes calldata data)
        external
        payable
        returns (
            RestrictTransferFrom.TransferType transferType,
            address receiver,
            address tokenIn
        )
    {
        if (data.length != 82) {
            revert UniswapV2Executor__InvalidDataLength();
        }
        tokenIn = address(bytes20(data[0:20]));
        receiver = address(bytes20(data[20:40]));
        transferType = RestrictTransferFrom.TransferType(uint8(data[81]));
    }
}
