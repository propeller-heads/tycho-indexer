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

    address public immutable factory;
    bytes32 public immutable initCode;
    address private immutable self;
    uint256 public immutable feeBps;

    constructor(address _factory, bytes32 _initCode, uint256 _feeBps) {
        if (_factory == address(0)) {
            revert UniswapV2Executor__InvalidFactory();
        }
        if (_initCode == bytes32(0)) {
            revert UniswapV2Executor__InvalidInitCode();
        }
        factory = _factory;
        initCode = _initCode;
        if (_feeBps > 30) {
            revert UniswapV2Executor__InvalidFee();
        }
        feeBps = _feeBps;
        self = address(this);
    }

    function canReceiveFromPreviousSwap(bytes calldata data)
        external
        returns (bool isOptimizable, address receiver)
    {
        address target = address(bytes20(data[0:20]));
        return (true, target);
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data, address receiver)
        external
        payable
        returns (uint256 calculatedAmount, address tokenOut)
    {
        address target;
        bool zeroForOne;

        (target, zeroForOne) = _decodeData(data);

        // Get token0 and token1 once to avoid redundant external calls
        IUniswapV2Pair pool = IUniswapV2Pair(target);
        address token0 = pool.token0();
        address token1 = pool.token1();

        _verifyPairAddress(target, token0, token1);

        calculatedAmount = _getAmountOut(target, amountIn, zeroForOne);

        // Infer tokenOut from zeroForOne
        tokenOut = zeroForOne ? token1 : token0;

        if (zeroForOne) {
            pool.swap(0, calculatedAmount, receiver, "");
        } else {
            pool.swap(calculatedAmount, 0, receiver, "");
        }
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (address target, bool zeroForOne)
    {
        if (data.length != 21) {
            revert UniswapV2Executor__InvalidDataLength();
        }
        target = address(bytes20(data[0:20]));
        zeroForOne = data[20] != 0;
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
        uint256 amountInWithFee = amountIn * (10000 - feeBps);
        uint256 numerator = amountInWithFee * uint256(reserveOut);
        uint256 denominator = (uint256(reserveIn) * 10000) + amountInWithFee;
        amount = numerator / denominator;
    }

    function _verifyPairAddress(address target, address token0, address token1)
        internal
        view
    {
        bytes32 salt = keccak256(abi.encodePacked(token0, token1));
        address pair = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(hex"ff", factory, salt, initCode)
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
            RestrictTransferFrom.TransferType baseTransferType,
            address receiver,
            address tokenIn
        )
    {
        if (data.length != 21) {
            revert UniswapV2Executor__InvalidDataLength();
        }
        address target = address(bytes20(data[0:20]));
        bool zeroForOne = data[20] != 0;

        IUniswapV2Pair pool = IUniswapV2Pair(target);
        address token0 = pool.token0();
        address token1 = pool.token1();
        tokenIn = zeroForOne ? token0 : token1;

        receiver = target;
        baseTransferType = RestrictTransferFrom.TransferType.Transfer;
    }
}
