// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IExecutor} from "@interfaces/IExecutor.sol";
import {ICore} from "@ekubo/interfaces/ICore.sol";
import {ILocker, IPayer} from "@ekubo/interfaces/IFlashAccountant.sol";
import {NATIVE_TOKEN_ADDRESS} from "@ekubo/math/constants.sol";
import {SafeTransferLib} from "@solady/utils/SafeTransferLib.sol";
import {LibBytes} from "@solady/utils/LibBytes.sol";
import {Config, EkuboPoolKey} from "@ekubo/types/poolKey.sol";
import {MAX_SQRT_RATIO, MIN_SQRT_RATIO} from "@ekubo/types/sqrtRatio.sol";

contract EkuboExecutor is IExecutor, ILocker, IPayer {
    error EkuboExecutor__InvalidDataLength();
    error EkuboExecutor__CoreOnly();
    error EkuboExecutor__UnknownCallback();

    ICore immutable core;

    uint256 constant POOL_DATA_OFFSET = 92;
    uint256 constant HOP_BYTE_LEN = 52;

    constructor(address _core) {
        core = ICore(_core);
    }

    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount)
    {
        if (data.length < 92) revert EkuboExecutor__InvalidDataLength();

        // amountIn must be at most type(int128).MAX
        calculatedAmount = uint256(_lock(bytes.concat(bytes16(uint128(amountIn)), data)));
    }

    function locked(uint256) external coreOnly {
        int128 nextAmountIn = int128(uint128(bytes16(msg.data[36:52])));
        uint128 tokenInDebtAmount = uint128(nextAmountIn);

        address receiver = address(bytes20(msg.data[52:72]));
        address tokenIn = address(bytes20(msg.data[72:POOL_DATA_OFFSET]));

        address nextTokenIn = tokenIn;

        uint256 hopsLength = (msg.data.length - POOL_DATA_OFFSET) / HOP_BYTE_LEN;

        uint256 offset = POOL_DATA_OFFSET;

        for (uint256 i = 0; i < hopsLength; i++) {
            address nextTokenOut =
                address(bytes20(LibBytes.loadCalldata(msg.data, offset)));
            Config poolConfig =
                Config.wrap(LibBytes.loadCalldata(msg.data, offset + 20));

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

        _pay(tokenIn, tokenInDebtAmount);

        core.withdraw(nextTokenIn, receiver, uint128(nextAmountIn));

        // slither-disable-next-line assembly
        assembly ("memory-safe") {
            mstore(0, nextAmountIn)
            return(0x10, 16)
        }
    }

    function payCallback(uint256, address token) external coreOnly {
        uint128 amount = uint128(bytes16(msg.data[68:84]));

        SafeTransferLib.safeTransfer(token, address(core), amount);
    }

    function _lock(bytes memory data) internal returns (uint128 swappedAmount) {
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

    function _pay(address token, uint128 amount) internal {
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

                // if it failed, pass through revert
                if iszero(call(gas(), target, 0, free, 52, 0, 0)) {
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
}
