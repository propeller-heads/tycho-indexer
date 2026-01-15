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

    uint256 constant POOL_DATA_OFFSET = 57;
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

    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount, address tokenOut, address receiver)
    {
        if (data.length < 92) {
            revert EkuboExecutor__InvalidDataLength();
        }

        // amountIn must be at most type(int128).MAX
        (calculatedAmount, tokenOut, receiver) =
            _lock(bytes.concat(bytes16(uint128(amountIn)), data));
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
            (int128 calculatedAmount, address tokenOut, address receiver) =
                _locked(stripped);
            result = abi.encodePacked(calculatedAmount, tokenOut, receiver);
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
        (int128 calculatedAmount, address tokenOut, address receiver) =
            _locked(msg.data[36:]);
        // slither-disable-next-line assembly
        assembly ("memory-safe") {
            // Pack: 16 bytes int128 + 20 bytes address + 20 bytes address = 56 bytes total
            mstore(0, shl(128, calculatedAmount)) // Store int128 in upper 16 bytes
            mstore(16, shl(96, tokenOut)) // Store address in upper 20 bytes (of next word)
            mstore(36, shl(96, receiver)) // Store address in upper 20 bytes (of next word)
            return(0, 56)
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
        returns (uint128 swappedAmount, address tokenOut, address receiver)
    {
        address target = address(core);

        // slither-disable-next-line assembly
        assembly ("memory-safe") {
            let args := mload(0x40)

            // Selector of lock()
            mstore(args, shl(224, 0xf83d08ba))

            // We only copy the data, not the length, because the length is read from the calldata size
            let len := mload(data)
            mcopy(add(args, 4), add(data, 32), len)

            // If the call failed, pass through the revert
            if iszero(call(gas(), target, 0, args, add(len, 36), 0, 0)) {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }

            // Copy 56 bytes: 16 bytes for amount + 20 bytes for address (tokenOut) + 20 bytes for address (receiver)
            returndatacopy(0, 0, 56)
            swappedAmount := shr(128, mload(0))
            tokenOut := shr(96, mload(16))
            receiver := shr(96, mload(36))
        }
    }

    function _locked(bytes calldata swapData)
        internal
        returns (int128, address, address)
    {
        int128 nextAmountIn = int128(uint128(bytes16(swapData[0:16])));
        uint128 tokenInDebtAmount = uint128(nextAmountIn);
        RestrictTransferFrom.TransferType transferType =
            RestrictTransferFrom.TransferType(uint8(swapData[16]));
        address receiver = address(bytes20(swapData[17:37]));
        address tokenIn = address(bytes20(swapData[37:57]));

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

        _pay(tokenIn, tokenInDebtAmount, transferType);
        core.withdraw(nextTokenIn, receiver, uint128(nextAmountIn));
        return (nextAmountIn, tokenOut, receiver);
    }

    function _forward(address to, bytes memory data)
        internal
        returns (bytes memory result)
    {
        address target = address(core);

        // slither-disable-next-line assembly
        assembly ("memory-safe") {
            // We will store result where the free memory pointer is now, ...
            result := mload(0x40)

            // But first use it to store the calldata

            // Selector of forward(address)
            mstore(result, shl(224, 0x101e8952))
            mstore(add(result, 4), to)

            // We only copy the data, not the length, because the length is read from the calldata size
            let len := mload(data)
            mcopy(add(result, 36), add(data, 32), len)

            // If the call failed, pass through the revert
            if iszero(call(gas(), target, 0, result, add(36, len), 0, 0)) {
                returndatacopy(result, 0, returndatasize())
                revert(result, returndatasize())
            }

            // Copy the entire return data into the space where the result is pointing
            mstore(result, returndatasize())
            returndatacopy(add(result, 32), 0, returndatasize())

            // Update the free memory pointer to be after the end of the data, aligned to the next 32 byte word
            mstore(
                0x40,
                and(add(add(result, add(32, returndatasize())), 31), not(31))
            )
        }
    }

    function _pay(
        address token,
        uint128 amount,
        RestrictTransferFrom.TransferType transferType
    ) internal {
        address target = address(core);

        if (token == NATIVE_TOKEN_ADDRESS) {
            SafeTransferLib.safeTransferETH(target, amount);
        } else {
            // slither-disable-next-line assembly
            assembly ("memory-safe") {
                let free := mload(0x40)
                // selector of pay(address)
                mstore(free, shl(224, 0x0c11dedd))
                mstore(add(free, 4), token)
                mstore(add(free, 36), shl(128, amount))
                mstore(add(free, 52), shl(248, transferType))

                // 4 (selector) + 32 (token) + 16 (amount) + 1 (transferType) = 53
                if iszero(call(gas(), target, 0, free, 53, 0, 0)) {
                    returndatacopy(0, 0, returndatasize())
                    revert(0, returndatasize())
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

        if (selector == PAY_CALLBACK_SELECTOR) {
            bytes calldata payData = data[36:];

            tokenIn = address(bytes20(payData[12:32]));
            amount = uint256(uint128(bytes16(payData[32:48])));
            transferType = RestrictTransferFrom.TransferType(uint8(payData[48]));
            receiver = address(core);
        } else {
            transferType = RestrictTransferFrom.TransferType.None;
            receiver = address(0);
            tokenIn = address(0);
            amount = 0;
        }
    }
}
