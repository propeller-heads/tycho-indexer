// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IExecutor} from "@interfaces/IExecutor.sol";
import {ICallback} from "@interfaces/ICallback.sol";
import {ICore} from "@ekubo/interfaces/ICore.sol";
import {ILocker, IPayer} from "@ekubo/interfaces/IFlashAccountant.sol";
import {NATIVE_TOKEN_ADDRESS} from "@ekubo/math/constants.sol";
import {SafeTransferLib} from "@solady/utils/SafeTransferLib.sol";
import {LibBytes} from "@solady/utils/LibBytes.sol";
import {Config, EkuboPoolKey} from "@ekubo/types/poolKey.sol";
import {MAX_SQRT_RATIO, MIN_SQRT_RATIO} from "@ekubo/types/sqrtRatio.sol";
import "../OneTransferFromOnly.sol";

contract EkuboExecutor is
    IExecutor,
    ILocker,
    IPayer,
    ICallback,
    OneTransferFromOnly
{
    error EkuboExecutor__InvalidDataLength();
    error EkuboExecutor__CoreOnly();
    error EkuboExecutor__UnknownCallback();

    ICore immutable core;

    uint256 constant POOL_DATA_OFFSET = 77;
    uint256 constant HOP_BYTE_LEN = 52;

    bytes4 constant LOCKED_SELECTOR = 0xb45a3c0e; // locked(uint256)
    bytes4 constant PAY_CALLBACK_SELECTOR = 0x599d0714; // payCallback(uint256,address)

    constructor(address _core, address _permit2)
        OneTransferFromOnly(_permit2)
    {
        core = ICore(_core);
    }

    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount)
    {
        if (data.length < 93) revert EkuboExecutor__InvalidDataLength();

        // amountIn must be at most type(int128).MAX
        calculatedAmount =
            uint256(_lock(bytes.concat(bytes16(uint128(amountIn)), data)));
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
            int128 calculatedAmount = _locked(stripped);
            result = abi.encodePacked(calculatedAmount);
        } else if (selector == PAY_CALLBACK_SELECTOR) {
            _payCallback(stripped);
        } else {
            revert EkuboExecutor__UnknownCallback();
        }

        return result;
    }

    function verifyCallback(bytes calldata) public view coreOnly {}

    function locked(uint256) external coreOnly {
        // Without selector and locker id
        int128 calculatedAmount = _locked(msg.data[36:]);
        // slither-disable-next-line assembly
        assembly ("memory-safe") {
            mstore(0, calculatedAmount)
            return(0x10, 16)
        }
    }

    function payCallback(uint256, address /*token*/ ) external coreOnly {
        // Without selector and locker id
        _payCallback(msg.data[36:]);
    }

    function _lock(bytes memory data)
        internal
        returns (uint128 swappedAmount)
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

            returndatacopy(0, 0, 16)
            swappedAmount := shr(128, mload(0))
        }
    }

    function _locked(bytes calldata swapData) internal returns (int128) {
        int128 nextAmountIn = int128(uint128(bytes16(swapData[0:16])));
        uint128 tokenInDebtAmount = uint128(nextAmountIn);
        address sender = address(bytes20(swapData[16:36]));
        bool transferFromNeeded = (swapData[36] != 0);
        bool transferNeeded = (swapData[37] != 0);

        address receiver = address(bytes20(swapData[38:58]));
        address tokenIn = address(bytes20(swapData[58:78]));

        address nextTokenIn = tokenIn;

        uint256 hopsLength = (swapData.length - POOL_DATA_OFFSET) / HOP_BYTE_LEN;

        uint256 offset = POOL_DATA_OFFSET;

        for (uint256 i = 0; i < hopsLength; i++) {
            address nextTokenOut =
                address(bytes20(LibBytes.loadCalldata(swapData, offset)));
            Config poolConfig =
                Config.wrap(LibBytes.loadCalldata(swapData, offset + 20));

            (address token0, address token1, bool isToken1) = nextTokenIn
                > nextTokenOut
                ? (nextTokenOut, nextTokenIn, true)
                : (nextTokenIn, nextTokenOut, false);

            // slither-disable-next-line calls-loop
            (int128 delta0, int128 delta1) = core.swap_611415377(
                EkuboPoolKey(token0, token1, poolConfig),
                nextAmountIn,
                isToken1,
                isToken1 ? MAX_SQRT_RATIO : MIN_SQRT_RATIO,
                0
            );

            nextTokenIn = nextTokenOut;
            nextAmountIn = -(isToken1 ? delta0 : delta1);

            offset += HOP_BYTE_LEN;
        }

        _pay(tokenIn, tokenInDebtAmount, transferFromNeeded, transferNeeded);
        core.withdraw(nextTokenIn, receiver, uint128(nextAmountIn));
        return nextAmountIn;
    }

    function _pay(
        address token,
        uint128 amount,
        bool transferFromNeeded,
        bool transferNeeded
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
                mstore(add(free, 52), shl(248, transferFromNeeded))
                mstore(add(free, 53), shl(248, transferNeeded))

                // 4 (selector) + 32 (token) + 16 (amount) + 1 (transferFromNeeded) + 1 (transferNeeded) = 54
                if iszero(call(gas(), target, 0, free, 54, 0, 0)) {
                    returndatacopy(0, 0, returndatasize())
                    revert(0, returndatasize())
                }
            }
        }
    }

    function _payCallback(bytes calldata payData) internal {
        address token = address(bytes20(payData[12:32])); // This arg is abi-encoded
        uint128 amount = uint128(bytes16(payData[32:48]));
        bool transferFromNeeded = (payData[48] != 0);
        bool transferNeeded = (payData[49] != 0);
        if (transferFromNeeded) {
            _transfer(msg.sender);
        } else if (transferNeeded) {
            if (token == address(0)) {
                payable(msg.sender).transfer(amount);
            } else {
                IERC20(token).transfer(msg.sender, amount);
            }
        }
    }

    // To receive withdrawals from Core
    receive() external payable {}

    modifier coreOnly() {
        if (msg.sender != address(core)) revert EkuboExecutor__CoreOnly();
        _;
    }
}
