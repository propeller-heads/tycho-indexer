// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {ICallback} from "@interfaces/ICallback.sol";
import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";

interface IFluidV1Dex {
    function swapInWithCallback(
        bool swap0to1_,
        uint256 amountIn_,
        uint256 amountOutMin_,
        address to_
    ) external payable returns (uint256 amountOut_);

    function swapIn(
        bool swap0to1_,
        uint256 amountIn_,
        uint256 amountOutMin_,
        address to_
    ) external payable returns (uint256 amountOut_);
}

error FluidV1Executor__ZeroLiquidityAddress();
error FluidV1Executor__InvalidDataLength();
error FluidV1Executor__InvalidCallback();

contract FluidV1Executor is IExecutor, ICallback {
    // keccak(FluidV1Executor#CURRENT_SWAP_PARAMS)
    // stores current dex address [0:20] and requested transfer type [31]
    bytes32 private constant _CURRENT_SWAP_PARAMS_SLOT =
        0x63858000ca86178f0c4d9faae7828d93c6063643b1a924a362f77d6933adbe94;
    // dexCallback(address,amount)
    bytes4 private constant CALLBACK_SELECTOR = 0x9410ae88;

    address public immutable LIQUIDITY;

    constructor(address _liquidity) {
        if (_liquidity == address(0)) {
            revert FluidV1Executor__ZeroLiquidityAddress();
        }
        LIQUIDITY = _liquidity;
    }

    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount, address tokenOut, address receiver)
    {
        IFluidV1Dex dex;
        bool zero2one;
        address tokenOut;
        address receiver;
        RestrictTransferFrom.TransferType transferType;
        bool isNativeSell;

        (dex, zero2one, tokenOut, receiver, transferType, isNativeSell) =
            _decodeData(data);

        if (!isNativeSell) {
            _setSwapParams(dex, transferType);
            calculatedAmount =
                dex.swapInWithCallback(zero2one, amountIn, 0, receiver);
        } else {
            // This is safe since the router asserts that we received the required output token in return
            // slither-disable-next-line arbitrary-send-eth
            calculatedAmount =
                dex.swapIn{value: amountIn}(zero2one, amountIn, 0, receiver);
        }
        // TODO: get token out
        tokenOut = address(0);
    }

    // Stores swap parameter packed into transient storage
    function _setSwapParams(
        IFluidV1Dex dex,
        RestrictTransferFrom.TransferType transferType
    ) internal {
        bytes32 value = bytes32(bytes20(address(dex)))
        | bytes32(uint256(transferType));
        // slither-disable-next-line assembly
        assembly {
            tstore(_CURRENT_SWAP_PARAMS_SLOT, value)
        }
    }

    function _getCurrentDex() internal view returns (address dex) {
        bytes32 value;
        // slither-disable-next-line assembly
        assembly {
            value := tload(_CURRENT_SWAP_PARAMS_SLOT)
        }
        dex = address(bytes20(value));
    }

    function _getTransferType()
        internal
        view
        returns (RestrictTransferFrom.TransferType)
    {
        uint256 value;
        // slither-disable-next-line assembly
        assembly {
            value := tload(_CURRENT_SWAP_PARAMS_SLOT)
        }
        return RestrictTransferFrom.TransferType(
            uint8(value & uint256(type(uint8).max))
        );
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            IFluidV1Dex dex,
            bool zero2one,
            address tokenOut,
            address receiver,
            RestrictTransferFrom.TransferType transferType,
            bool isNativeSell
        )
    {
        // expected calldata layout
        // ---------------------
        // 0  | dex address
        // 20 | zero2one
        // 21 | tokenOut
        // 41 | receiver
        // 61 | transferType
        // 62 | is_native
        // 63 | EOF
        if (data.length != 63) {
            revert FluidV1Executor__InvalidDataLength();
        }
        dex = IFluidV1Dex(address(bytes20(data[0:20])));
        zero2one = uint8(data[20]) > 0;
        tokenOut = address(bytes20(data[21:41]));
        receiver = address(bytes20(data[41:61]));
        transferType = RestrictTransferFrom.TransferType(uint8(data[61]));
        isNativeSell = uint8(data[62]) > 0;
    }

    function handleCallback(bytes calldata data)
        public
        returns (bytes memory result)
    {
        verifyCallback(data);
        result = "";
    }

    function verifyCallback(bytes calldata data) public view {
        address dex = _getCurrentDex();
        bytes4 selector = bytes4(data[:4]);
        if (msg.sender != dex || selector != CALLBACK_SELECTOR) {
            revert FluidV1Executor__InvalidCallback();
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
        (tokenIn, amount) = abi.decode(data[4:68], (address, uint256));
        transferType = _getTransferType();
        receiver = LIQUIDITY;
    }
}
