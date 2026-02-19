// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {ICallback} from "@interfaces/ICallback.sol";
import {
    IERC20,
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {
    Currency,
    CurrencyLibrary
} from "@uniswap/v4-core/src/types/Currency.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PathKey} from "@uniswap/v4-periphery/src/libraries/PathKey.sol";
import {
    IUnlockCallback
} from "@uniswap/v4-core/src/interfaces/callback/IUnlockCallback.sol";
import {
    SafeCast as V4SafeCast
} from "@uniswap/v4-core/src/libraries/SafeCast.sol";
import {
    TransientStateLibrary
} from "@uniswap/v4-core/src/libraries/TransientStateLibrary.sol";
import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {
    LibPrefixLengthEncodedByteArray
} from "../../lib/bytes/LibPrefixLengthEncodedByteArray.sol";

error UniswapV4Executor__InvalidDataLength();
error UniswapV4Executor__NotPoolManager();
error UniswapV4Executor__UnknownCallback(bytes4 selector);
error UniswapV4Executor__DeltaNotPositive(Currency currency);
error UniswapV4Executor__DeltaNotNegative(Currency currency);
error UniswapV4Executor__V4TooMuchRequested(
    uint256 maxAmountInRequested, uint256 amountRequested
);
error UniswapV4Executor__InvalidAngstromAttestationDataLength(uint256 length);
error UniswapV4Executor__ZeroAddressAngstromHook();

contract UniswapV4Executor is IExecutor, ICallback {
    using SafeERC20 for IERC20;
    using CurrencyLibrary for Currency;
    using V4SafeCast for *;
    using TransientStateLibrary for IPoolManager;
    using LibPrefixLengthEncodedByteArray for bytes;

    bytes4 private constant _SWAP_EXACT_INPUT_SELECTOR = 0xc4881bc7;
    bytes4 private constant _SWAP_EXACT_INPUT_SINGLE_SELECTOR = 0x105c1b93;

    IPoolManager public immutable poolManager;
    address private immutable _angstromHookAddress;
    address private immutable _self;

    struct UniswapV4Pool {
        address intermediaryToken;
        uint24 fee;
        int24 tickSpacing;
        address hook;
        bytes hookData;
    }

    constructor(IPoolManager poolManager_, address angstromHook) {
        if (angstromHook == address(0)) {
            revert UniswapV4Executor__ZeroAddressAngstromHook();
        }
        poolManager = poolManager_;
        _angstromHookAddress = angstromHook;
        _self = address(this);
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

    /**
     * @dev Modifier to restrict access to only the pool manager.
     */
    modifier poolManagerOnly() virtual {
        if (msg.sender != address(poolManager)) {
            revert UniswapV4Executor__NotPoolManager();
        }
        _;
    }

    function swap(uint256 amountIn, bytes calldata data, address receiver)
        external
        payable
        returns (uint256 amountOut, address tokenOut)
    {
        address tokenIn;
        bool zeroForOne;
        UniswapV4Executor.UniswapV4Pool[] memory pools;
        (tokenIn, tokenOut, zeroForOne, pools) = _decodeData(data);
        bytes memory swapData;
        if (pools.length == 1) {
            PoolKey memory key = PoolKey({
                currency0: Currency.wrap(zeroForOne ? tokenIn : tokenOut),
                currency1: Currency.wrap(zeroForOne ? tokenOut : tokenIn),
                fee: pools[0].fee,
                tickSpacing: pools[0].tickSpacing,
                hooks: IHooks(pools[0].hook)
            });
            swapData = abi.encodeWithSelector(
                this.swapExactInputSingle.selector,
                key,
                zeroForOne,
                amountIn,
                receiver,
                pools[0].hookData
            );
        } else {
            PathKey[] memory path = new PathKey[](pools.length);
            for (uint256 i = 0; i < pools.length; i++) {
                path[i] = PathKey({
                    intermediateCurrency: Currency.wrap(
                        pools[i].intermediaryToken
                    ),
                    fee: pools[i].fee,
                    tickSpacing: pools[i].tickSpacing,
                    hooks: IHooks(pools[i].hook),
                    hookData: pools[i].hookData
                });
            }

            Currency currencyIn = Currency.wrap(tokenIn);
            swapData = abi.encodeWithSelector(
                this.swapExactInput.selector,
                currencyIn,
                amountIn,
                receiver,
                path
            );
        }
        poolManager.sync(Currency.wrap(tokenIn));
        bytes memory result = poolManager.unlock(swapData);
        amountOut = abi.decode(result, (uint128));
    }

    // slither-disable-next-line dead-code
    function _decodeData(bytes calldata data)
        internal
        view
        virtual
        returns (
            address tokenIn,
            address tokenOut,
            bool zeroForOne,
            UniswapV4Pool[] memory pools
        )
    {
        if (data.length < 89) {
            revert UniswapV4Executor__InvalidDataLength();
        }

        tokenIn = address(bytes20(data[0:20]));
        tokenOut = address(bytes20(data[20:40]));
        zeroForOne = data[40] != 0;

        bytes calldata remaining = data[41:];

        // Decode first pool with hook data
        if (remaining.length < 48) {
            // 20 + 3 + 3 + 20 + 2 = 48 minimum
            revert UniswapV4Executor__InvalidDataLength();
        }

        address firstToken = address(bytes20(remaining[0:20]));
        uint24 firstFee = uint24(bytes3(remaining[20:23]));
        int24 firstTickSpacing = int24(uint24(bytes3(remaining[23:26])));
        address firstHook = address(bytes20(remaining[26:46]));
        uint16 firstHookDataLength = uint16(bytes2(remaining[46:48]));

        uint256 firstPoolTotalLength = 48 + firstHookDataLength;
        if (remaining.length < firstPoolTotalLength) {
            revert UniswapV4Executor__InvalidDataLength();
        }

        bytes memory firstHookData;
        if (firstHook == _angstromHookAddress) {
            // Select attestation from first pool's hook data
            // Convert calldata to memory since _selectAttestation requires bytes memory
            firstHookData = _selectAttestation(
                bytes(remaining[48:48 + firstHookDataLength])
            );
        } else {
            firstHookData = bytes(remaining[48:48 + firstHookDataLength]);
        }

        // Remaining after first pool are ple encoded
        bytes[] memory encodedPools = LibPrefixLengthEncodedByteArray.toArray(
            remaining[firstPoolTotalLength:]
        );

        pools = new UniswapV4Pool[](1 + encodedPools.length);
        pools[0] = UniswapV4Pool(
            firstToken, firstFee, firstTickSpacing, firstHook, firstHookData
        );

        // Decode subsequent pools
        for (uint256 i = 0; i < encodedPools.length; i++) {
            bytes memory poolData = encodedPools[i];

            address intermediaryToken;
            uint24 fee;
            int24 tickSpacing;
            address hook;
            uint16 hookDataLength;

            // slither-disable-next-line assembly
            assembly {
                let dataPtr := add(poolData, 0x20)
                intermediaryToken := shr(96, mload(dataPtr))
                fee := and(shr(232, mload(add(dataPtr, 20))), 0xffffff)
                tickSpacing := and(shr(208, mload(add(dataPtr, 20))), 0xffffff)
                hook := shr(96, mload(add(dataPtr, 26)))
                hookDataLength := and(shr(240, mload(add(dataPtr, 46))), 0xffff)
            }

            if (poolData.length < 48 + hookDataLength) {
                revert UniswapV4Executor__InvalidDataLength();
            }

            // Extract hookData bytes for this pool
            // We copy byte-by-byte because we cannot slice bytes memory in Solidity
            bytes memory rawHookData = new bytes(hookDataLength);
            for (uint256 j = 0; j < hookDataLength; j++) {
                rawHookData[j] = poolData[48 + j];
            }

            bytes memory hookData;
            if (hook == _angstromHookAddress) {
                // Select attestation from hookData
                hookData = _selectAttestation(rawHookData);
            } else {
                hookData = rawHookData;
            }

            pools[i + 1] = UniswapV4Pool(
                intermediaryToken, fee, tickSpacing, hook, hookData
            );
        }
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
     * @dev Internal function to handle the unlock callback.
     */
    function _unlockCallback(bytes calldata data)
        internal
        returns (bytes memory)
    {
        bytes4 selector = bytes4(data[:4]);
        if (
            selector != _SWAP_EXACT_INPUT_SELECTOR
                && selector != _SWAP_EXACT_INPUT_SINGLE_SELECTOR
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
     * @param receiver The address of the receiver.
     * @param hookData Additional data for hook contracts.
     */
    function swapExactInputSingle(
        PoolKey memory poolKey,
        bool zeroForOne,
        uint128 amountIn,
        address receiver,
        bytes calldata hookData
    ) external returns (uint128) {
        Currency currencyIn = zeroForOne ? poolKey.currency0 : poolKey.currency1;
        _settle(currencyIn, amountIn);
        uint128 amountOut = _swap(
                poolKey, zeroForOne, -int256(uint256(amountIn)), hookData
            ).toUint128();

        Currency currencyOut =
            zeroForOne ? poolKey.currency1 : poolKey.currency0;
        _take(currencyOut, receiver, _mapTakeAmount(amountOut, currencyOut));
        return amountOut;
    }

    /**
     * @notice Performs an exact input swap along a path. It settles and takes the tokens after the swap.
     * @param currencyIn The currency of the input token.
     * @param amountIn The amount of tokens to swap in.
     * @param receiver The address of the receiver.
     * @param path The path to swap along.
     */
    function swapExactInput(
        Currency currencyIn,
        uint128 amountIn,
        address receiver,
        PathKey[] calldata path
    ) external returns (uint128) {
        uint128 amountOut = 0;
        Currency swapCurrencyIn = currencyIn;
        uint256 swapAmountIn = amountIn;
        _settle(currencyIn, amountIn);
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
                SwapParams(
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

    /**
     * @notice Pays and settles a currency to the pool manager.
     * @dev The implementing contract must ensure that the `payer` is a secure address.
     * @param currency The currency to settle.
     * @param amount The amount to send.
     * @dev Returns early if the amount is 0.
     */
    function _settle(Currency currency, uint256 amount) internal {
        if (amount == 0) return;
        if (currency.isAddressZero()) {
            // slither-disable-next-line unused-return
            poolManager.settle{value: amount}();
        } else {
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

    /// @notice Selects the appropriate attestation for the current block number
    /// @dev Each attestation is exactly 93 bytes: 8 bytes blockNumber + 85 bytes attestation
    /// @param attestationData Raw bytes of encoded attestations for several blocks
    /// @return The attestation bytes for the current block, or empty bytes if no attestation found
    function _selectAttestation(bytes memory attestationData)
        internal
        view
        returns (bytes memory)
    {
        uint256 totalLength = 93;
        bytes memory attestation = new bytes(85);

        // Calculate number of attestations from data length
        if (attestationData.length % totalLength != 0) {
            revert UniswapV4Executor__InvalidAngstromAttestationDataLength(attestationData.length);
        }

        uint256 attestationCount = attestationData.length / totalLength;

        for (uint256 i = 0; i < attestationCount; i++) {
            uint256 offset = i * totalLength;

            // Assembly is used because attestationData is bytes memory
            uint64 blockNumber;
            // slither-disable-next-line assembly
            assembly {
                // Load block number (8 bytes) - shift right to get the first 8 bytes
                blockNumber := shr(
                    192,
                    mload(add(add(attestationData, 0x20), offset))
                )

                // Copy attestation (85 bytes)
                let src := add(add(attestationData, 0x20), add(offset, 8))
                let dst := add(attestation, 0x20)

                // Copy 85 bytes (2 full words + 21 bytes)
                mstore(dst, mload(src)) // Copy first 32 bytes
                mstore(add(dst, 0x20), mload(add(src, 0x20))) // Copy next 32 bytes
                mstore(add(dst, 0x40), mload(add(src, 0x40))) // Copy remaining 21 bytes (loads 32, but we only need 21)
            }

            // If we find the attestation for the current block, stop decoding early
            // and return the attestation.
            // slither-disable-next-line incorrect-equality
            if (blockNumber == block.number) {
                return attestation;
            }
        }

        // All attestations decoded and no attestation found for the current block.
        // Return empty bytes instead of reverting
        return "";
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
        bytes calldata stripped = data[68:];
        bytes4 selector = bytes4(stripped[:4]);
        receiver = address(poolManager);
        if (selector == _SWAP_EXACT_INPUT_SINGLE_SELECTOR) {
            // swapExactInputSingle(PoolKey memory poolKey, bool zeroForOne, uint128 amountIn, address receiver, bytes calldata hookData)
            // Data layout: selector(4) + PoolKey(160) + bool(32) + uint128(32) + address(32) + hookData(variable)

            // PoolKey starts at offset 4, each field is 32 bytes:
            // currency0: data[4:36], currency1: data[36:68], fee: data[68:100], tickSpacing: data[100:132], hooks: data[132:164]
            // zeroForOne: data[164:196]
            // amountIn: data[196:228]
            // receiver: data[228:260]

            bool zeroForOne = uint8(stripped[195]) != 0;
            amount = uint128(bytes16(stripped[212:228]));
            // Extract tokenIn from PoolKey based on zeroForOne
            if (zeroForOne) {
                tokenIn = address(bytes20(stripped[16:36])); // currency0
            } else {
                tokenIn = address(bytes20(stripped[48:68])); // currency1
            }
            if (tokenIn == address(0)) {
                // ETH transfers are handled in the Executor, so we need to set the transferType to
                // TransferNativeInExecutor to update the delta accounting accordingly.
                transferType =
                RestrictTransferFrom.TransferType.TransferNativeInExecutor;
            } else {
                transferType = RestrictTransferFrom.TransferType.Transfer;
            }
        } else if (selector == _SWAP_EXACT_INPUT_SELECTOR) {
            // swapExactInput(Currency currencyIn, uint128 amountIn, address receiver, PathKey[] calldata path)
            // Data layout: selector(4) + Currency(32) + uint128(32) + address(32) + PathKey[](variable)

            tokenIn = address(bytes20(stripped[16:36]));
            amount = uint128(bytes16(stripped[52:68]));
            if (tokenIn == address(0)) {
                // ETH transfers are handled in the Executor, so we need to set the transferType to
                // TransferNativeInExecutor to update the delta accounting accordingly.
                transferType =
                RestrictTransferFrom.TransferType.TransferNativeInExecutor;
            } else {
                transferType = RestrictTransferFrom.TransferType.Transfer;
            }
        } else {
            revert UniswapV4Executor__UnknownCallback(selector);
        }
    }
}
