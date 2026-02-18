// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {
    SafeERC20,
    IERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";
import {
    RefundEscrow
} from "../../lib/permit2/lib/openzeppelin-contracts/contracts/utils/escrow/RefundEscrow.sol";

error MaverickV2Executor__InvalidDataLength();
error MaverickV2Executor__InvalidTarget();
error MaverickV2Executor__InvalidFactory();

contract MaverickV2Executor is IExecutor {
    using SafeERC20 for IERC20;

    address public immutable factory;

    constructor(address factory_) {
        if (factory_ == address(0)) {
            revert MaverickV2Executor__InvalidFactory();
        }
        factory = factory_;
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
        returns (uint256 amountOut, address tokenOut)
    {
        address target;
        IERC20 tokenIn;

        (target, tokenIn, tokenOut) = _decodeData(data);

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
        (, amountOut) = pool.swap(receiver, swapParams, "");
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (address target, IERC20 inToken, address tokenOut)
    {
        if (data.length != 60) {
            revert MaverickV2Executor__InvalidDataLength();
        }
        target = address(bytes20(data[0:20]));
        inToken = IERC20(address(bytes20(data[20:40])));
        tokenOut = address(bytes20(data[40:60]));
    }

    function _verifyPairAddress(address target) internal view {
        if (!IMaverickV2Factory(factory).isFactoryPool(IMaverickV2Pool(target)))
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
        if (data.length != 60) {
            revert MaverickV2Executor__InvalidDataLength();
        }
        receiver = address(bytes20(data[0:20]));
        tokenIn = address(bytes20(data[20:40]));
        transferType = RestrictTransferFrom.TransferType.Transfer;
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
