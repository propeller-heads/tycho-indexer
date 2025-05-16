// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/Address.sol";

error MaverickV2Executor__InvalidDataLength();
error MaverickV2Executor__InvalidTarget();
error MaverickV2Executor__InvalidFactory();

contract MaverickV2Executor is IExecutor {
    using SafeERC20 for IERC20;

    address public immutable factory;

    constructor(address _factory) {
        if (_factory == address(0)) {
            revert MaverickV2Executor__InvalidFactory();
        }
        factory = _factory;
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 givenAmount, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount)
    {
        address target;
        address receiver;
        IERC20 tokenIn;
        bool transferNeeded;

        (tokenIn, target, receiver, transferNeeded) = _decodeData(data);

        _verifyPairAddress(target);
        IMaverickV2Pool pool = IMaverickV2Pool(target);

        bool isTokenAIn = pool.tokenA() == tokenIn;
        int32 tickLimit = isTokenAIn ? type(int32).max : type(int32).min;
        IMaverickV2Pool.SwapParams memory swapParams = IMaverickV2Pool
            .SwapParams({
            amount: givenAmount,
            tokenAIn: isTokenAIn,
            exactOutput: false,
            tickLimit: tickLimit
        });

        if (transferNeeded) {
            if (address(tokenIn) == address(0)) {
                Address.sendValue(payable(target), givenAmount);
            } else {
                // slither-disable-next-line arbitrary-send-erc20
                tokenIn.safeTransfer(target, givenAmount);
            }
        }

        // slither-disable-next-line unused-return
        (, calculatedAmount) = pool.swap(receiver, swapParams, "");
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            IERC20 inToken,
            address target,
            address receiver,
            bool transferNeeded
        )
    {
        if (data.length != 61) {
            revert MaverickV2Executor__InvalidDataLength();
        }
        inToken = IERC20(address(bytes20(data[0:20])));
        target = address(bytes20(data[20:40]));
        receiver = address(bytes20(data[40:60]));
        transferNeeded = (data[60] != 0);
    }

    function _verifyPairAddress(address target) internal view {
        if (!IMaverickV2Factory(factory).isFactoryPool(IMaverickV2Pool(target)))
        {
            revert MaverickV2Executor__InvalidTarget();
        }
    }
}

interface IMaverickV2Factory {
    function isFactoryPool(IMaverickV2Pool pool) external view returns (bool);
}

interface IMaverickV2Pool {
    struct SwapParams {
        uint256 amount;
        bool tokenAIn;
        bool exactOutput;
        int32 tickLimit;
    }

    function swap(
        address recipient,
        SwapParams memory params,
        bytes calldata data
    ) external returns (uint256 amountIn, uint256 amountOut);

    function tokenA() external view returns (IERC20);
    function tokenB() external view returns (IERC20);
}
