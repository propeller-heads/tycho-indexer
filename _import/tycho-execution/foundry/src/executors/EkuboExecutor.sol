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
import {Config, PoolKey} from "@ekubo/types/poolKey.sol";
import {MAX_SQRT_RATIO, MIN_SQRT_RATIO} from "@ekubo/types/sqrtRatio.sol";

contract EkuboExecutor is IExecutor, ICallback, ILocker, IPayer {
    error EkuboExecutor__InvalidDataLength();
    error EkuboExecutor__CoreOnly();
    error EkuboExecutor__UnknownCallback();

    ICore immutable core;

    uint256 constant POOL_DATA_OFFSET = 56;
    uint256 constant HOP_BYTE_LEN = 52;

    constructor(ICore _core) {
        core = _core;
    }

    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount)
    {
        if (data.length < 92) revert EkuboExecutor__InvalidDataLength();

        uint256 tokenOutOffset = data.length - HOP_BYTE_LEN;
        address tokenOut = address(bytes20(LibBytes.loadCalldata(data, tokenOutOffset)));

        uint256 tokenOutBalanceBefore = _balanceOf(tokenOut);

        // amountIn must be at most type(int128).MAX
        _lock(bytes.concat(bytes16(uint128(amountIn)), data));

        uint256 tokenOutBalanceAfter = _balanceOf(tokenOut);

        // It would be better if we could somehow pass back the swapped amount from the lock but the interface doesn't offer that capability.
        // Note that the current approach also prevents arbs that return less than their input because of arithmetic underflow.
        calculatedAmount = tokenOutBalanceAfter - tokenOutBalanceBefore;
    }

    // We can't use the return value here since it won't get propagated (see Dispatcher.sol:_handleCallback)
    function handleCallback(bytes calldata raw)
        external
        returns (bytes memory)
    {
        verifyCallback(raw);

        // Without selector and locker id
        bytes calldata stripped = raw[36:];

        bytes4 selector = bytes4(raw[:4]);

        if (selector == 0xb45a3c0e) { // Selector of locked(uint256)
            _locked(stripped);
        } else if (selector == 0x599d0714) { // Selector of payCallback(uint256,address)
            _payCallback(stripped);
        } else {
            revert EkuboExecutor__UnknownCallback();
        }

        return "";
    }

    function verifyCallback(bytes calldata) public view coreOnly {}

    function locked(uint256) external coreOnly {
        // Without selector and locker id
        _locked(msg.data[36:]);
    }

    function payCallback(uint256, address token) external coreOnly {
        uint128 amount = uint128(bytes16(LibBytes.loadCalldata(msg.data, 68)));

        SafeTransferLib.safeTransfer(token, address(core), amount);
    }

    function _balanceOf(address token) internal view returns (uint256 balance) {
        balance = token == NATIVE_TOKEN_ADDRESS
            ? address(this).balance
            : IERC20(token).balanceOf(address(this));
    }

    function _lock(bytes memory data) internal {
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
        }
    }

    function _locked(bytes calldata swapData) internal {
        // For partial swaps this is not equivalent to the given input amount
        uint128 tokenInDebtAmount = 0;

        int128 nextAmountIn = int128(uint128(bytes16(swapData[0:16])));

        address receiver = address(bytes20(swapData[16:36]));
        address tokenIn = address(bytes20(swapData[36:POOL_DATA_OFFSET]));

        address nextTokenIn = tokenIn;

        uint256 hopsLength = (swapData.length - POOL_DATA_OFFSET) / HOP_BYTE_LEN;

        uint256 offset = POOL_DATA_OFFSET;

        for (uint256 i = 0; i < hopsLength; i++) {
            address nextTokenOut = address(bytes20(LibBytes.loadCalldata(swapData, offset)));
            Config poolConfig = Config.wrap(LibBytes.loadCalldata(swapData, offset + 20));

            (
                address token0,
                address token1,
                bool isToken1
            ) = nextTokenIn > nextTokenOut ? (
                nextTokenOut,
                nextTokenIn,
                true
            ) : (
                nextTokenIn,
                nextTokenOut,
                false
            );

            (int128 delta0, int128 delta1) = core.swap_611415377(
                PoolKey(token0, token1, poolConfig),
                nextAmountIn,
                isToken1,
                isToken1 ? MAX_SQRT_RATIO : MIN_SQRT_RATIO,
                0
            );

            if (tokenInDebtAmount == 0) {
                tokenInDebtAmount = uint128(isToken1 ? delta1 : delta0);
            }

            nextTokenIn = nextTokenOut;
            nextAmountIn = -(isToken1 ? delta0 : delta1);

            offset += HOP_BYTE_LEN;
        }

        _pay(tokenIn, tokenInDebtAmount);

        core.withdraw(
            nextTokenIn,
            receiver,
            uint128(nextAmountIn)
        );
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

    function _payCallback(bytes calldata payData) internal {
        address token = address(bytes20(payData[0:20]));
        uint128 amount = uint128(bytes16(payData[20:36]));

        SafeTransferLib.safeTransfer(address(core), token, amount);
    }

    // To receive withdrawals from Core
    receive() external payable {}

    modifier coreOnly() {
        if (msg.sender != address(core)) revert EkuboExecutor__CoreOnly();
        _;
    }
}
