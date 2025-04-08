// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@uniswap-v2/contracts/interfaces/IUniswapV2Pair.sol";
import "./ExecutorTransferMethods.sol";

error UniswapV2Executor__InvalidDataLength();
error UniswapV2Executor__InvalidTarget();
error UniswapV2Executor__InvalidFactory();
error UniswapV2Executor__InvalidInitCode();

contract UniswapV2Executor is IExecutor, ExecutorTransferMethods {
    using SafeERC20 for IERC20;

    address public immutable factory;
    bytes32 public immutable initCode;
    address private immutable self;

    constructor(address _factory, bytes32 _initCode, address _permit2)
        ExecutorTransferMethods(_permit2)
    {
        if (_factory == address(0)) {
            revert UniswapV2Executor__InvalidFactory();
        }
        if (_initCode == bytes32(0)) {
            revert UniswapV2Executor__InvalidInitCode();
        }
        factory = _factory;
        initCode = _initCode;
        self = address(this);
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 givenAmount, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount)
    {
        IERC20 tokenIn;
        address target;
        address receiver;
        bool zeroForOne;
        TransferMethod method;

        (tokenIn, target, receiver, zeroForOne, method) = _decodeData(data);

        _verifyPairAddress(target);

        calculatedAmount = _getAmountOut(target, givenAmount, zeroForOne);
        _transfer(tokenIn, msg.sender, target, givenAmount, method);

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
            IERC20 inToken,
            address target,
            address receiver,
            bool zeroForOne,
            TransferMethod method
        )
    {
        if (data.length != 62) {
            revert UniswapV2Executor__InvalidDataLength();
        }
        inToken = IERC20(address(bytes20(data[0:20])));
        target = address(bytes20(data[20:40]));
        receiver = address(bytes20(data[40:60]));
        zeroForOne = uint8(data[60]) > 0;
        method = TransferMethod(uint8(data[61]));
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
        uint256 amountInWithFee = amountIn * 997;
        uint256 numerator = amountInWithFee * uint256(reserveOut);
        uint256 denominator = (uint256(reserveIn) * 1000) + amountInWithFee;
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
                        abi.encodePacked(hex"ff", factory, salt, initCode)
                    )
                )
            )
        );
        if (pair != target) {
            revert UniswapV2Executor__InvalidTarget();
        }
    }
}
