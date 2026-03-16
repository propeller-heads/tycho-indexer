pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {
    SafeERC20,
    IERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {
    IUniswapV2Pair
} from "@uniswap-v2/contracts/interfaces/IUniswapV2Pair.sol";
import {TransferManager} from "../TransferManager.sol";

error UniswapV2Executor__InvalidDataLength();
error UniswapV2Executor__InvalidTarget();
error UniswapV2Executor__InvalidFactory();
error UniswapV2Executor__InvalidInitCode();
error UniswapV2Executor__InvalidFee();

contract UniswapV2Executor is IExecutor {
    using SafeERC20 for IERC20;

    address public immutable factory;
    bytes32 public immutable initCode;
    uint256 public immutable feeBps;
    address private immutable _self;

    constructor(address factory_, bytes32 initCode_, uint256 feeBps_) {
        if (factory_ == address(0)) {
            revert UniswapV2Executor__InvalidFactory();
        }
        if (initCode_ == bytes32(0)) {
            revert UniswapV2Executor__InvalidInitCode();
        }
        factory = factory_;
        initCode = initCode_;
        if (feeBps_ > 30) {
            revert UniswapV2Executor__InvalidFee();
        }
        feeBps = feeBps_;
        _self = address(this);
    }

    function fundsExpectedAddress(bytes calldata data)
        external
        pure
        returns (address receiver)
    {
        address target = address(bytes20(data[0:20]));
        return target;
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data, address receiver)
        external
        payable
        returns (uint256 calculatedAmount, address tokenOut)
    {
        address target;
        address tokenIn;
        bool isFoT;

        (target, tokenIn, tokenOut, isFoT) = _decodeData(data);

        bool zeroForOne = (tokenIn < tokenOut);
        address token0 = zeroForOne ? tokenIn : tokenOut;
        address token1 = zeroForOne ? tokenOut : tokenIn;

        _verifyPairAddress(target, token0, token1);

        IUniswapV2Pair pool = IUniswapV2Pair(target);

        if (isFoT) {
            calculatedAmount =
                _swapFoT(pool, tokenIn, tokenOut, zeroForOne, receiver);
        } else {
            calculatedAmount = _swap(pool, amountIn, zeroForOne, receiver);
        }
    }

    function _swap(
        IUniswapV2Pair pool,
        uint256 amountIn,
        bool zeroForOne,
        address receiver
    ) internal returns (uint256 calculatedAmount) {
        // slither-disable-next-line unused-return
        (uint112 reserve0, uint112 reserve1,) = pool.getReserves();
        uint112 reserveIn = zeroForOne ? reserve0 : reserve1;
        uint112 reserveOut = zeroForOne ? reserve1 : reserve0;

        calculatedAmount = _getAmountOut(amountIn, reserveIn, reserveOut);

        if (zeroForOne) {
            pool.swap(0, calculatedAmount, receiver, "");
        } else {
            pool.swap(calculatedAmount, 0, receiver, "");
        }
    }

    function _swapFoT(
        IUniswapV2Pair pool,
        address tokenIn,
        address tokenOut,
        bool zeroForOne,
        address receiver
    ) internal returns (uint256 calculatedAmount) {
        // slither-disable-next-line unused-return
        (uint112 reserve0, uint112 reserve1,) = pool.getReserves();
        uint112 reserveIn = zeroForOne ? reserve0 : reserve1;
        uint112 reserveOut = zeroForOne ? reserve1 : reserve0;

        // Measure actual balance to handle input transfer tax
        uint256 actualAmountIn =
            IERC20(tokenIn).balanceOf(address(pool)) - uint256(reserveIn);

        calculatedAmount = _getAmountOut(actualAmountIn, reserveIn, reserveOut);

        uint256 balanceBefore = IERC20(tokenOut).balanceOf(receiver);

        if (zeroForOne) {
            pool.swap(0, calculatedAmount, receiver, "");
        } else {
            pool.swap(calculatedAmount, 0, receiver, "");
        }

        // Measure actual received to handle output transfer tax
        calculatedAmount = IERC20(tokenOut).balanceOf(receiver) - balanceBefore;
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (address target, address tokenIn, address tokenOut, bool isFoT)
    {
        if (data.length != 61) {
            revert UniswapV2Executor__InvalidDataLength();
        }
        target = address(bytes20(data[0:20]));
        tokenIn = address(bytes20(data[20:40]));
        tokenOut = address(bytes20(data[40:60]));
        isFoT = data[60] != 0;
    }

    function _getAmountOut(
        uint256 amountIn,
        uint112 reserveIn,
        uint112 reserveOut
    ) internal view returns (uint256 amount) {
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
            TransferManager.TransferType transferType,
            address receiver,
            address tokenIn,
            address tokenOut,
            bool outputToRouter
        )
    {
        if (data.length != 61) {
            revert UniswapV2Executor__InvalidDataLength();
        }
        address target = address(bytes20(data[0:20]));
        tokenIn = address(bytes20(data[20:40]));
        tokenOut = address(bytes20(data[40:60]));

        receiver = target;
        transferType = TransferManager.TransferType.Transfer;
        outputToRouter = false;
    }
}
