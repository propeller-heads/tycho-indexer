// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import {IERC20, SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Currency, CurrencyLibrary} from "@uniswap/v4-core/src/types/Currency.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IUnlockCallback} from "@uniswap/v4-core/src/interfaces/callback/IUnlockCallback.sol";
import {TransientStateLibrary} from "@uniswap/v4-core/src/libraries/TransientStateLibrary.sol";
import {V4Router} from "@uniswap/v4-periphery/src/V4Router.sol";
import {Actions} from "@uniswap/v4-periphery/src/libraries/Actions.sol";
import {IV4Router} from "@uniswap/v4-periphery/src/interfaces/IV4Router.sol";
import {Permit2Payments} from "../../lib/Permit2Payments.sol";

error UniswapV4Executor__InvalidDataLength();
error UniswapV4Executor__SwapFailed();
error UniswapV4Executor__InsufficientOutput();
error UniswapV4Executor__ManagerMismatch();

contract UniswapV4Executor is IExecutor, V4Router {
    using SafeERC20 for IERC20;
    using CurrencyLibrary for Currency;
    using SafeCast for int128;
    using SafeCast for int256;
    using TransientStateLibrary for IPoolManager;

    uint256 private constant MIN_SQRT_RATIO = 4295128739;
    uint256 private constant MAX_SQRT_RATIO =
        1461446703485210103287273052203988822378723970342;

    constructor(IPoolManager _poolManager) V4Router(_poolManager) {}

    function swap(
        uint256 amountIn,
        bytes calldata data
    ) external payable returns (uint256 amountOut) {
        (
            address tokenIn,
            address tokenOut,
            uint24 fee,
            address receiver, // TODO: Investigate
            bool zeroForOne
        ) = _decodeData(data);

        uint128 amountIn128 = uint128(amountIn);
        uint128 amountOut128 = uint128(amountOut);
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(zeroForOne ? tokenIn : tokenOut),
            currency1: Currency.wrap(zeroForOne ? tokenOut : tokenIn),
            fee: fee,
            tickSpacing: 60, // Standard tick spacing
            hooks: IHooks(address(0)) // No hooks needed for basic swaps
        });

        bytes memory actions = abi.encodePacked(
            uint8(Actions.SWAP_EXACT_IN_SINGLE),
            uint8(Actions.SETTLE_ALL),
            uint8(Actions.TAKE_ALL)
        );

        bytes[] memory params = new bytes[](3);

        params[0] = abi.encode(
            IV4Router.ExactInputSingleParams({
                poolKey: key,
                zeroForOne: zeroForOne,
                amountIn: amountIn128,
                amountOutMinimum: amountOut128,
                hookData: bytes("")
            })
        );

        params[1] = abi.encode(key.currency0, amountIn128);
        params[2] = abi.encode(key.currency1, amountOut128);

        // Convert the encoded parameters to calldata format
        bytes memory encodedActions = abi.encode(actions, params);
        (bool success, ) = address(this).call(
            abi.encodeWithSelector(this.executeActions.selector, encodedActions)
        );

        if (!success) {
            revert UniswapV4Executor__SwapFailed();
        }

        return amountOut;
    }

    function executeActions(bytes calldata actions) external {
        _executeActions(actions);
    }

    function _decodeData(
        bytes calldata data
    )
        internal
        pure
        returns (
            address tokenIn,
            address tokenOut,
            uint24 fee,
            address receiver,
            bool zeroForOne
        )
    {
        if (data.length != 64) {
            revert UniswapV4Executor__InvalidDataLength();
        }

        tokenIn = address(bytes20(data[:20]));
        tokenOut = address(bytes20(data[20:40]));
        fee = uint24(bytes3(data[40:43]));
        receiver = address(bytes20(data[43:63]));
        zeroForOne = uint8(bytes1(data[63])) > 0;
    }

    function _pay(
        Currency token,
        address payer,
        uint256 amount
    ) internal override {
        // TODO: Implement
    }

    function msgSender() public view override returns (address) {
        return msg.sender;
    }
}
