// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {
    SafeERC20,
    IERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";
import {RefundEscrow} from "../../lib/permit2/lib/openzeppelin-contracts/contracts/utils/escrow/RefundEscrow.sol";

    error MaverickV2Executor__InvalidDataLength();
error MaverickV2Executor__InvalidTarget();
error MaverickV2Executor__InvalidFactory();

contract MaverickV2Executor is IExecutor {
    using SafeERC20 for IERC20;

    address public immutable FACTORY;

    constructor(address _factory) {
        if (_factory == address(0)) {
            revert MaverickV2Executor__InvalidFactory();
        }
        FACTORY = _factory;
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount, address tokenOut, address receiver)
    {
        address target;
        IERC20 tokenIn;

        (tokenIn, target, tokenOut, receiver) = _decodeData(data);

        _verifyPairAddress(target);
        IMaverickV2Pool pool = IMaverickV2Pool(target);

        bool isTokenAIn = pool.tokenA() == tokenIn;
        int32 tickLimit = isTokenAIn ? type(int32).max : type(int32).min;
        IMaverickV2Pool.SwapParams memory swapParams = IMaverickV2Pool.SwapParams({
            amount: amountIn,
            tokenAIn: isTokenAIn,
            exactOutput: false,
            tickLimit: tickLimit
        });

        // slither-disable-next-line unused-return
        (, calculatedAmount) = pool.swap(receiver, swapParams, "");
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (IERC20 inToken, address target, address tokenOut,
            address receiver)
    {
        if (data.length != 81) {
            revert MaverickV2Executor__InvalidDataLength();
        }
        inToken = IERC20(address(bytes20(data[0:20])));
        target = address(bytes20(data[20:40]));
        tokenOut = address(bytes20(data[40:60]));
        receiver = address(bytes20(data[60:80]));
    }

    function _verifyPairAddress(address target) internal view {
        if (!IMaverickV2Factory(FACTORY).isFactoryPool(IMaverickV2Pool(target)))
        {
            revert MaverickV2Executor__InvalidTarget();
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
        if (data.length != 81) {
            revert MaverickV2Executor__InvalidDataLength();
        }
        tokenIn = address(bytes20(data[0:20]));
        receiver = address(bytes20(data[20:40]));
        transferType = RestrictTransferFrom.TransferType(uint8(data[80]));
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
