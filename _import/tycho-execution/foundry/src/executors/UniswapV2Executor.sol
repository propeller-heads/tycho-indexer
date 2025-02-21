// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@uniswap-v2/contracts/interfaces/IUniswapV2Pair.sol";

error UniswapV2Executor__InvalidDataLength();
error UniswapV2Executor__InvalidTarget();

contract UniswapV2Executor is IExecutor {
    using SafeERC20 for IERC20;

    address private constant FACTORY =
        0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f;

    // slither-disable-next-line locked-ether
    function swap(uint256 givenAmount, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount)
    {
        address target;
        address receiver;
        bool zeroForOne;
        IERC20 tokenIn;

        (tokenIn, target, receiver, zeroForOne) = _decodeData(data);

        if (target != _computePairAddress(target)) {
            revert UniswapV2Executor__InvalidTarget();
        }
        calculatedAmount = _getAmountOut(target, givenAmount, zeroForOne);
        tokenIn.safeTransfer(target, givenAmount);

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
            bool zeroForOne
        )
    {
        if (data.length != 61) {
            revert UniswapV2Executor__InvalidDataLength();
        }
        inToken = IERC20(address(bytes20(data[0:20])));
        target = address(bytes20(data[20:40]));
        receiver = address(bytes20(data[40:60]));
        zeroForOne = uint8(data[60]) > 0;
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

    function _computePairAddress(address target)
        internal
        view
        returns (address pair)
    {
        address token0 = IUniswapV2Pair(target).token0();
        address token1 = IUniswapV2Pair(target).token1();
        bytes32 salt = keccak256(abi.encodePacked(token0, token1));
        pair = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            hex"ff",
                            FACTORY,
                            salt,
                            hex"96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f"
                        )
                    )
                )
            )
        );
    }
}
