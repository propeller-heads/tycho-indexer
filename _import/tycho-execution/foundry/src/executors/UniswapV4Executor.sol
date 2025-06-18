// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import {ICallback} from "@interfaces/ICallback.sol";
import {
    IERC20,
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {
    Currency, CurrencyLibrary
} from "@uniswap/v4-core/src/types/Currency.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PathKey} from "@uniswap/v4-periphery/src/libraries/PathKey.sol";
import {IUnlockCallback} from
    "@uniswap/v4-core/src/interfaces/callback/IUnlockCallback.sol";
import {SafeCast} from "@uniswap/v4-core/src/libraries/SafeCast.sol";
import {TransientStateLibrary} from
    "@uniswap/v4-core/src/libraries/TransientStateLibrary.sol";
import "../RestrictTransferFrom.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "../../lib/bytes/LibPrefixLengthEncodedByteArray.sol";

error UniswapV4Executor__InvalidDataLength();
error UniswapV4Executor__NotPoolManager();
error UniswapV4Executor__UnknownCallback(bytes4 selector);
error UniswapV4Executor__DeltaNotPositive(Currency currency);
error UniswapV4Executor__DeltaNotNegative(Currency currency);
error UniswapV4Executor__V4TooMuchRequested(
    uint256 maxAmountInRequested, uint256 amountRequested
);

contract UniswapV4Executor is
    IExecutor,
    IUnlockCallback,
    ICallback,
    RestrictTransferFrom
{
    using SafeERC20 for IERC20;
    using CurrencyLibrary for Currency;
    using SafeCast for *;
    using TransientStateLibrary for IPoolManager;
    using LibPrefixLengthEncodedByteArray for bytes;

    IPoolManager public immutable poolManager;
    address private immutable _self;

    bytes4 constant SWAP_EXACT_INPUT_SINGLE_SELECTOR = 0x6022fbcd;
    bytes4 constant SWAP_EXACT_INPUT_SELECTOR = 0x044f0d3d;

    struct UniswapV4Pool {
        address intermediaryToken;
        uint24 fee;
        int24 tickSpacing;
    }

    constructor(IPoolManager _poolManager, address _permit2)
        RestrictTransferFrom(_permit2)
    {
        poolManager = _poolManager;
        _self = address(this);
    }

    /**
     * @dev Modifier to restrict access to only the pool manager.
     */
    modifier poolManagerOnly() virtual {
        if (msg.sender != address(poolManager)) {
            revert UniswapV4Executor__NotPoolManager();
        }
        _;
    }

    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount)
    {
        (
            address tokenIn,
            address tokenOut,
            bool zeroForOne,
            TransferType transferType,
            address receiver,
            address hook,
            bytes memory hookData,
            UniswapV4Executor.UniswapV4Pool[] memory pools
        ) = _decodeData(data);
        bytes memory swapData;
        if (pools.length == 1) {
            PoolKey memory key = PoolKey({
                currency0: Currency.wrap(zeroForOne ? tokenIn : tokenOut),
                currency1: Currency.wrap(zeroForOne ? tokenOut : tokenIn),
                fee: pools[0].fee,
                tickSpacing: pools[0].tickSpacing,
                hooks: IHooks(hook)
            });
            swapData = abi.encodeWithSelector(
                this.swapExactInputSingle.selector,
                key,
                zeroForOne,
                amountIn,
                transferType,
                receiver,
                hookData
            );
        } else {
            PathKey[] memory path = new PathKey[](pools.length);
            for (uint256 i = 0; i < pools.length; i++) {
                path[i] = PathKey({
                    intermediateCurrency: Currency.wrap(pools[i].intermediaryToken),
                    fee: pools[i].fee,
                    tickSpacing: pools[i].tickSpacing,
                    hooks: IHooks(hook),
                    hookData: hookData
                });
            }

            Currency currencyIn = Currency.wrap(tokenIn);
            swapData = abi.encodeWithSelector(
                this.swapExactInput.selector,
                currencyIn,
                path,
                amountIn,
                transferType,
                receiver
            );
        }

        bytes memory result = poolManager.unlock(swapData);
        uint128 amountOut = abi.decode(result, (uint128));

        return amountOut;
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            address tokenIn,
            address tokenOut,
            bool zeroForOne,
            TransferType transferType,
            address receiver,
            address hook,
            bytes memory hookData,
            UniswapV4Pool[] memory pools
        )
    {
        if (data.length < 108) {
            revert UniswapV4Executor__InvalidDataLength();
        }

        tokenIn = address(bytes20(data[0:20]));
        tokenOut = address(bytes20(data[20:40]));
        zeroForOne = data[40] != 0;
        transferType = TransferType(uint8(data[41]));
        receiver = address(bytes20(data[42:62]));
        hook = address(bytes20(data[62:82]));

        bytes calldata remaining = data[82:];
        address firstToken = address(bytes20(remaining[0:20]));
        uint24 firstFee = uint24(bytes3(remaining[20:23]));
        int24 firstTickSpacing = int24(uint24(bytes3(remaining[23:26])));
        UniswapV4Pool memory firstPool =
            UniswapV4Pool(firstToken, firstFee, firstTickSpacing);

        // Remaining after first pool are ple encoded
        bytes[] memory encodedPools =
            LibPrefixLengthEncodedByteArray.toArray(remaining[26:]);

        pools = new UniswapV4Pool[](1 + encodedPools.length);
        pools[0] = firstPool;

        uint256 encodedPoolsLength = 26;
        uint256 plePoolsTotalLength;

        for (uint256 i = 0; i < encodedPools.length; i++) {
            bytes memory poolsData = encodedPools[i];
            address intermediaryToken;
            uint24 fee;
            int24 tickSpacing;

            // slither-disable-next-line assembly
            assembly {
                intermediaryToken := mload(add(poolsData, add(0, 20)))
                fee := shr(232, mload(add(poolsData, add(0, 52))))
                tickSpacing := shr(232, mload(add(poolsData, add(0, 55))))
            }
            pools[i + 1] = UniswapV4Pool(intermediaryToken, fee, tickSpacing);
            plePoolsTotalLength += 2 + encodedPoolsLength; // 2 bytes prefix + data
        }

        hookData = remaining[26 + plePoolsTotalLength:];
    }

    /**
     * @notice Handles the callback from the pool manager. This is used for callbacks from the router.
     */
    function handleCallback(bytes calldata data)
        external
        returns (bytes memory)
    {
        bytes calldata stripped = data[68:];
        verifyCallback(stripped);
        // Our general callback logic returns a not ABI encoded result.
        // However, the pool manager expects the result to be ABI encoded. That is why we need to encode it here again.
        return abi.encode(_unlockCallback(stripped));
    }

    function verifyCallback(bytes calldata) public view poolManagerOnly {}

    /**
     * @notice Handles the unlock callback from the pool manager. This is used for swaps against the executor directly (bypassing the router).
     */
    function unlockCallback(bytes calldata data)
        external
        poolManagerOnly
        returns (bytes memory)
    {
        return _unlockCallback(data);
    }

    /**
     * @dev Internal function to handle the unlock callback.
     */
    function _unlockCallback(bytes calldata data)
        internal
        returns (bytes memory)
    {
        bytes4 selector = bytes4(data[:4]);
        if (
            selector != SWAP_EXACT_INPUT_SELECTOR
                && selector != SWAP_EXACT_INPUT_SINGLE_SELECTOR
        ) {
            revert UniswapV4Executor__UnknownCallback(selector);
        }

        // here we expect to call either `swapExactInputSingle` or `swapExactInput`. See `swap` to see how we encode the selector and the calldata
        // slither-disable-next-line low-level-calls
        (bool success, bytes memory returnData) = _self.delegatecall(data);
        if (!success) {
            revert(
                string(
                    returnData.length > 0
                        ? returnData
                        : abi.encodePacked("Uniswap v4 Callback failed")
                )
            );
        }
        return returnData;
    }

    /**
     * @notice Performs an exact input single swap. It settles and takes the tokens after the swap.
     * @param poolKey The key of the pool to swap in.
     * @param zeroForOne Whether the swap is from token0 to token1 (true) or vice versa (false).
     * @param amountIn The amount of tokens to swap in.
     * @param transferType The type of action necessary to pay back the pool.
     * @param receiver The address of the receiver.
     * @param hookData Additional data for hook contracts.
     */
    function swapExactInputSingle(
        PoolKey memory poolKey,
        bool zeroForOne,
        uint128 amountIn,
        TransferType transferType,
        address receiver,
        bytes calldata hookData
    ) external returns (uint128) {
        uint128 amountOut = _swap(
            poolKey, zeroForOne, -int256(uint256(amountIn)), hookData
        ).toUint128();

        Currency currencyIn = zeroForOne ? poolKey.currency0 : poolKey.currency1;
        uint256 amount = _getFullDebt(currencyIn);
        if (amount > amountIn) {
            revert UniswapV4Executor__V4TooMuchRequested(amountIn, amount);
        }
        _settle(currencyIn, amount, transferType);

        Currency currencyOut =
            zeroForOne ? poolKey.currency1 : poolKey.currency0;
        _take(currencyOut, receiver, _mapTakeAmount(amountOut, currencyOut));
        return amountOut;
    }

    /**
     * @notice Performs an exact input swap along a path. It settles and takes the tokens after the swap.
     * @param currencyIn The currency of the input token.
     * @param path The path to swap along.
     * @param amountIn The amount of tokens to swap in.
     * @param transferType The type of action necessary to pay back the pool.
     * @param receiver The address of the receiver.
     */
    function swapExactInput(
        Currency currencyIn,
        PathKey[] calldata path,
        uint128 amountIn,
        TransferType transferType,
        address receiver
    ) external returns (uint128) {
        uint128 amountOut = 0;
        Currency swapCurrencyIn = currencyIn;
        uint256 swapAmountIn = amountIn;
        unchecked {
            uint256 pathLength = path.length;
            PathKey calldata pathKey;

            for (uint256 i = 0; i < pathLength; i++) {
                pathKey = path[i];
                (PoolKey memory poolKey, bool zeroForOne) =
                    pathKey.getPoolAndSwapDirection(swapCurrencyIn);
                // The output delta will always be positive, except for when interacting with certain hook pools
                amountOut = _swap(
                    poolKey,
                    zeroForOne,
                    -int256(uint256(swapAmountIn)),
                    pathKey.hookData
                ).toUint128();

                swapAmountIn = amountOut;
                swapCurrencyIn = pathKey.intermediateCurrency;
            }
        }

        uint256 amount = _getFullDebt(currencyIn);
        if (amount > amountIn) {
            revert UniswapV4Executor__V4TooMuchRequested(amountIn, amount);
        }
        _settle(currencyIn, amount, transferType);

        _take(
            swapCurrencyIn, // at the end of the loop this is actually currency out
            receiver,
            _mapTakeAmount(amountOut, swapCurrencyIn)
        );
        return amountOut;
    }

    function _swap(
        PoolKey memory poolKey,
        bool zeroForOne,
        int256 amountSpecified,
        bytes calldata hookData
    ) private returns (int128 reciprocalAmount) {
        unchecked {
            // slither-disable-next-line calls-loop
            BalanceDelta delta = poolManager.swap(
                poolKey,
                IPoolManager.SwapParams(
                    zeroForOne,
                    amountSpecified,
                    zeroForOne
                        ? TickMath.MIN_SQRT_PRICE + 1
                        : TickMath.MAX_SQRT_PRICE - 1
                ),
                hookData
            );

            reciprocalAmount = (zeroForOne == amountSpecified < 0)
                ? delta.amount1()
                : delta.amount0();
        }
    }

    /**
     * @notice Obtains the full amount owed by this contract (negative delta).
     * @param currency The currency to get the delta for.
     * @return amount The amount owed by this contract.
     */
    function _getFullCredit(Currency currency)
        internal
        view
        returns (uint256 amount)
    {
        int256 _amount = poolManager.currencyDelta(address(this), currency);
        // If the amount is negative, it should be settled not taken.
        if (_amount < 0) revert UniswapV4Executor__DeltaNotPositive(currency);
        amount = uint256(_amount);
    }

    /// @notice Obtain the full amount owed by this contract (negative delta)
    /// @param currency Currency to get the delta for
    /// @return amount The amount owed by this contract as a uint256
    function _getFullDebt(Currency currency)
        internal
        view
        returns (uint256 amount)
    {
        int256 _amount = poolManager.currencyDelta(address(this), currency);
        // If the amount is positive, it should be taken not settled.
        if (_amount > 0) revert UniswapV4Executor__DeltaNotNegative(currency);
        // Casting is safe due to limits on the total supply of a pool
        amount = uint256(-_amount);
    }

    /**
     * @notice Pays and settles a currency to the pool manager.
     * @dev The implementing contract must ensure that the `payer` is a secure address.
     * @param currency The currency to settle.
     * @param amount The amount to send.
     * @param transferType The type of action necessary to pay back the pool.
     * @dev Returns early if the amount is 0.
     */
    function _settle(
        Currency currency,
        uint256 amount,
        TransferType transferType
    ) internal {
        if (amount == 0) return;
        poolManager.sync(currency);
        if (currency.isAddressZero()) {
            // slither-disable-next-line unused-return
            poolManager.settle{value: amount}();
        } else {
            _transfer(
                address(poolManager),
                transferType,
                Currency.unwrap(currency),
                amount
            );
            // slither-disable-next-line unused-return
            poolManager.settle();
        }
    }

    /**
     * @notice Takes an amount of currency out of the pool manager.
     * @param currency The currency to take.
     * @param recipient The address to receive the currency.
     * @param amount The amount to take.
     * @dev Returns early if the amount is 0.
     */
    function _take(Currency currency, address recipient, uint256 amount)
        internal
    {
        if (amount == 0) return;
        poolManager.take(currency, recipient, amount);
    }

    function _mapTakeAmount(uint256 amount, Currency currency)
        internal
        view
        returns (uint256)
    {
        if (amount == 0) {
            return _getFullCredit(currency);
        } else {
            return amount;
        }
    }
}
