// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {
    SafeERC20,
    IERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IExecutor} from "@interfaces/IExecutor.sol";
import {ICallback} from "@interfaces/ICallback.sol";
import {ICore} from "@ekubo/interfaces/ICore.sol";
import {ILocker, IPayer} from "@ekubo/interfaces/IFlashAccountant.sol";
import {NATIVE_TOKEN_ADDRESS} from "@ekubo/math/constants.sol";
import {SafeTransferLib} from "@solady/utils/SafeTransferLib.sol";
import {LibBytes} from "@solady/utils/LibBytes.sol";
import {Config, PoolKey} from "@ekubo/types/poolKey.sol";
import {
    MAX_SQRT_RATIO,
    MIN_SQRT_RATIO,
    SqrtRatio
} from "@ekubo/types/sqrtRatio.sol";
import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

contract EkuboExecutor is IExecutor, ILocker, IPayer, ICallback {
    error EkuboExecutor__AddressZero();
    error EkuboExecutor__InvalidDataLength();
    error EkuboExecutor__CoreOnly();
    error EkuboExecutor__UnknownCallback();

    ICore immutable core;
    address immutable mevResist;

    uint256 constant POOL_DATA_OFFSET = 56;
    uint256 constant HOP_BYTE_LEN = 52;

    bytes4 constant LOCKED_SELECTOR = 0xb45a3c0e; // locked(uint256)
    bytes4 constant PAY_CALLBACK_SELECTOR = 0x599d0714; // payCallback(uint256,address)

    uint256 constant SKIP_AHEAD = 0;

    using SafeERC20 for IERC20;

    constructor(address _core, address _mevResist) {
        core = ICore(_core);

        if (_mevResist == address(0)) {
            revert EkuboExecutor__AddressZero();
        }
        mevResist = _mevResist;
    }

    function fundsExpectedAddress(
        bytes calldata /* data */
    )
        external
        view
        returns (address receiver)
    {
        return msg.sender;
    }

    function swap(uint256 amountIn, bytes calldata data, address receiver)
        external
        payable
        returns (uint256 amountOut, address tokenOut)
    {
        if (data.length < 72) {
            revert EkuboExecutor__InvalidDataLength();
        }

        // amountIn must be at most type(int128).MAX
        (amountOut, tokenOut) = _lock(
            abi.encodePacked(
                bytes16(uint128(amountIn)), bytes20(receiver), data
            )
        );
    }

    function handleCallback(bytes calldata raw)
        external
        returns (bytes memory)
    {
        verifyCallback(raw);

        // Without selector and locker id
        bytes calldata stripped = raw[36:];

        bytes4 selector = bytes4(raw[:4]);

        bytes memory result = "";
        if (selector == LOCKED_SELECTOR) {
            (int128 amountOut, address tokenOut) = _locked(stripped);
            result = abi.encodePacked(amountOut, tokenOut);
        } else if (selector == PAY_CALLBACK_SELECTOR) {
            // The paying is done in the Dispatcher using getCallbackTransferData. Nothing to do here
        } else {
            revert EkuboExecutor__UnknownCallback();
        }

        return result;
    }

    function verifyCallback(bytes calldata) public view coreOnly {}

    function locked(uint256) external coreOnly {
        // Without selector and locker id
        (int128 amountOut, address tokenOut) = _locked(msg.data[36:]);

        // Pack: 16 bytes int128 + 20 bytes address = 36 bytes total
        bytes memory result = abi.encodePacked(amountOut, tokenOut);

        // slither-disable-next-line assembly
        assembly ("memory-safe") {
            // Return raw bytes without ABI encoding
            return(add(result, 32), mload(result))
        }
    }

    function payCallback(
        uint256,
        address /*token*/
    )
        external
        coreOnly
    {
        // The paying is done in the Dispatcher using getCallbackTransferData. Nothing to do here
    }

    function _lock(bytes memory data)
        internal
        returns (uint128 swappedAmount, address tokenOut)
    {
        // Prepend selector of lock() to calldata
        // We must use assembly here since the Ekubo Core's lock method expects the raw
        // bytes directly and not ABI-encoded bytes
        bytes memory callData = abi.encodePacked(bytes4(0xf83d08ba), data);

        // slither-disable-next-line low-level-calls
        (bool success, bytes memory result) = address(core).call(callData);

        if (!success) {
            // slither-disable-next-line assembly
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }

        // Decode 36 bytes: 16 bytes for int128 + 20 bytes for address
        // Data is packed with values left-shifted in each position
        // Assembly is necessary since the input is bytes memory and not bytes calldata
        int128 amountOut;
        // slither-disable-next-line assembly
        assembly ("memory-safe") {
            amountOut := shr(128, mload(add(result, 32)))
            tokenOut := shr(96, mload(add(result, 48)))
        }
        swappedAmount = uint128(amountOut);
    }

    function _locked(bytes calldata swapData)
        internal
        returns (int128, address)
    {
        int128 nextAmountIn = int128(uint128(bytes16(swapData[0:16])));
        uint128 tokenInDebtAmount = uint128(nextAmountIn);
        address receiver = address(bytes20(swapData[16:36]));
        address tokenIn = address(bytes20(swapData[36:56]));

        address nextTokenIn = tokenIn;
        address nextTokenOut = address(0);

        uint256 hopsLength = (swapData.length - POOL_DATA_OFFSET) / HOP_BYTE_LEN;

        uint256 offset = POOL_DATA_OFFSET;

        for (uint256 i = 0; i < hopsLength; i++) {
            nextTokenOut =
                address(bytes20(LibBytes.loadCalldata(swapData, offset)));
            Config poolConfig =
                Config.wrap(LibBytes.loadCalldata(swapData, offset + 20));

            (
                address token0,
                address token1,
                bool isToken1,
                SqrtRatio sqrtRatioLimit
            ) = nextTokenIn > nextTokenOut
                ? (nextTokenOut, nextTokenIn, true, MAX_SQRT_RATIO)
                : (nextTokenIn, nextTokenOut, false, MIN_SQRT_RATIO);

            PoolKey memory pk = PoolKey(token0, token1, poolConfig);

            int128 delta0;
            int128 delta1;

            if (poolConfig.extension() == mevResist) {
                (delta0, delta1) = abi.decode(
                    _forward(
                        mevResist,
                        abi.encode(
                            pk,
                            nextAmountIn,
                            isToken1,
                            sqrtRatioLimit,
                            SKIP_AHEAD
                        )
                    ),
                    (int128, int128)
                );
            } else {
                // slither-disable-next-line calls-loop
                (delta0, delta1) = core.swap_611415377(
                    pk, nextAmountIn, isToken1, sqrtRatioLimit, SKIP_AHEAD
                );
            }

            nextTokenIn = nextTokenOut;
            nextAmountIn = -(isToken1 ? delta0 : delta1);

            offset += HOP_BYTE_LEN;
        }

        // After the loop, nextTokenOut is the final output token
        address tokenOut = nextTokenOut;

        _pay(tokenIn, tokenInDebtAmount);
        core.withdraw(nextTokenIn, receiver, uint128(nextAmountIn));
        return (nextAmountIn, tokenOut);
    }

    function _forward(address to, bytes memory data)
        internal
        returns (bytes memory result)
    {
        // Prepend forward(address) selector to the data
        // We must use assembly here since the Ekubo Core's lock method expects the raw
        // bytes directly and not ABI-encoded bytes
        bytes memory callData = abi.encodePacked(
            bytes4(0x101e8952), bytes32(uint256(uint160(to))), data
        );

        // slither-disable-next-line low-level-calls,calls-loop
        (bool success, bytes memory returnData) = address(core).call(callData);

        // Assembly is necessary to be able to revert with arbitrary bytes memory
        if (!success) {
            // slither-disable-next-line assembly
            assembly ("memory-safe") {
                revert(add(returnData, 32), mload(returnData))
            }
        }

        return returnData;
    }

    function _pay(address token, uint128 amount) internal {
        if (token == NATIVE_TOKEN_ADDRESS) {
            SafeTransferLib.safeTransferETH(address(core), amount);
        } else {
            bytes memory callData = abi.encodePacked(
                bytes4(0x0c11dedd), // pay(address) selector
                bytes32(uint256(uint160(token))),
                bytes16(amount)
            );

            // slither-disable-next-line low-level-calls
            (bool success, bytes memory result) = address(core).call(callData);

            if (!success) {
                // slither-disable-next-line assembly
                assembly ("memory-safe") {
                    revert(add(result, 32), mload(result))
                }
            }
        }
    }

    // To receive withdrawals from Core
    receive() external payable {}

    modifier coreOnly() {
        if (msg.sender != address(core)) revert EkuboExecutor__CoreOnly();
        _;
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
        bytes4 selector = bytes4(data[:4]);
        bytes calldata payData = data[36:];
        if (selector == PAY_CALLBACK_SELECTOR) {
            tokenIn = address(bytes20(payData[12:32]));
            amount = uint256(uint128(bytes16(payData[32:48])));
            transferType = RestrictTransferFrom.TransferType.Transfer;
            receiver = address(core);
        } else {
            // LOCKED_SELECTOR
            address tokenInFromCallback = address(bytes20(payData[36:56]));
            if (tokenInFromCallback == address(0)) {
                // ETH transfers are handled in the Executor, so we need to set the transferType to
                // TransferNativeInExecutor to update the delta accounting accordingly.
                tokenIn = address(0);
                transferType =
                RestrictTransferFrom.TransferType.TransferNativeInExecutor;
                amount = uint256(uint128(bytes16(payData[0:16])));
            } else {
                transferType = RestrictTransferFrom.TransferType.None;
                receiver = address(0);
                tokenIn = address(0);
                amount = 0;
            }
        }
    }
}
