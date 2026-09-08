// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {
    ReentrancyGuardTransient
} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {
    SafeERC20,
    IERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {
    IUniswapV2Pair
} from "@uniswap-v2/contracts/interfaces/IUniswapV2Pair.sol";
import {
    IUniswapV3Pool
} from "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IPropAMM} from "@interfaces/IPropAMM.sol";
import {
    CryptoPool as ICurveCryptoPool,
    StablePool as ICurveStablePool
} from "../executors/CurveExecutor.sol";
import {IFluidV1Dex} from "../executors/FluidV1Executor.sol";
import {UniswapV2Math} from "../../lib/UniswapV2Math.sol";

error TychoFallbackRouter__AddressZero();
error TychoFallbackRouter__CallbackTokenMismatch(
    address requested, address expected
);
error TychoFallbackRouter__InvalidCallback();
error TychoFallbackRouter__InvalidSwapLength(uint256 length);
error TychoFallbackRouter__InvalidUniswapV2Fee(uint256 feeBps);
error TychoFallbackRouter__NoOutput();
error TychoFallbackRouter__NotPoolManager();
error TychoFallbackRouter__NotSelf();
error TychoFallbackRouter__UnknownVenue(uint8 venue);
error TychoFallbackRouter__ZeroGasCap();

/// @title TychoFallbackRouter
/// @notice Runs a primary venue and, only if it fails, the caller's chosen fallback venue.
/// The primary is always a pAMM; the fallback never is.
/// @dev Exists because an executor cannot fall back: the Dispatcher transfers a leg's input before
/// it delegatecalls `swap()`, so a reverting pAMM has already been paid and a Uniswap V3 retry,
/// which pays in a callback, cannot be funded. Here the tokens stay in this contract.
///
/// Holds no funds and grants no allowances between transactions. Native ETH unsupported.
contract TychoFallbackRouter is AccessControl, ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    enum Venue {
        UniswapV2,
        UniswapV3,
        UniswapV4,
        Curve,
        FluidV1
    }

    /// @notice One swap leg: what goes in, what comes out, and who receives it.
    struct Leg {
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        address receiver;
    }

    struct UniswapV4Swap {
        Leg leg;
        uint24 fee;
        int24 tickSpacing;
        address hook;
        bytes hookData;
    }

    /// @notice May call `swap`. Granted to the TychoRouter, so held balances
    /// cannot be swept by strangers naming their own pAMM.
    //keccak256("CALLER_ROLE") : save gas on deployment
    bytes32 public constant CALLER_ROLE =
        0x843c3a00fa95510a35f425371231fd3fe4642e719cb4595160763d6d02594b50;

    // keccak256("TychoFallbackRouter#CALLBACK_SOURCE")
    bytes32 private constant _CALLBACK_SOURCE_SLOT =
        0xf69ae8e0008b818aeb91c2b052698e485056e760fad9d0aa28144b842debe4f7;
    // keccak256("TychoFallbackRouter#CALLBACK_TOKEN")
    bytes32 private constant _CALLBACK_TOKEN_SLOT =
        0xbb428614797396c24d2ae21e3c7c9a28d69673f64cb7ba6433b600b67ed8541b;
    // keccak256("TychoFallbackRouter#CALLBACK_AMOUNT")
    bytes32 private constant _CALLBACK_AMOUNT_SLOT =
        0xde66fd0ca9c728ba44ca7bab17a304d328bf9cf5d5c72b8bf8ea7cd13765e542;

    IPoolManager public immutable poolManager;
    /// @notice Where `dexCallback` pays a Fluid dex.
    address public immutable fluidLiquidity;

    /// @notice Gas forwarded to the pAMM try. Bounds what a gas-burning pAMM
    /// can consume, so the fallback always keeps enough to fill; a pAMM
    /// needing more than this falls back instead of filling.
    uint256 public pammGasCap = 1_000_000;

    event Rescued(
        address indexed token, address indexed receiver, uint256 amount
    );
    event PammGasCapUpdated(uint256 oldCap, uint256 newCap);

    constructor(
        address admin,
        IPoolManager poolManager_,
        address fluidLiquidity_
    ) {
        if (
            admin == address(0) || address(poolManager_) == address(0)
                || fluidLiquidity_ == address(0)
        ) {
            revert TychoFallbackRouter__AddressZero();
        }
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        poolManager = poolManager_;
        fluidLiquidity = fluidLiquidity_;
    }

    /// @notice Runs `pamm` and, only if it fails, `fallbackSwap`. A failing fallback reverts the
    /// swap; there is no third attempt.
    /// @dev Only callers holding `CALLER_ROLE` (the TychoRouter). Push-payment: the caller MUST
    /// transfer `leg.amountIn` of `leg.tokenIn` here first. Native ETH is not supported.
    /// `fallbackSwap` is `[venue: uint8][venue data]`, and no venue kind is a pAMM.
    /// No output is returned: the caller measures its own `leg.tokenOut` balance diff at
    /// `leg.receiver`, which is how the Dispatcher verifies every leg.
    function swap(Leg calldata leg, address pamm, bytes calldata fallbackSwap)
        external
        nonReentrant
        onlyRole(CALLER_ROLE)
    {
        // The try/catch is what unwinds the pAMM's transfer. Only the pAMM gets one: the fallback
        // is the caller's chosen venue, so its revert is the swap's revert. The gas cap keeps a
        // pAMM that fails by consuming gas from starving the fallback -- an uncapped call returns
        // only 1/64 of the gas it burns (EIP-150).
        // slither-disable-next-line reentrancy-events
        try this.executePropAMM{gas: pammGasCap}(leg, pamm) {
            return;
        } catch {}

        _executeFallback(leg, fallbackSwap);
    }

    /// @notice Runs the pAMM. External only so `swap` can try/catch it.
    function executePropAMM(Leg calldata leg, address pamm) external {
        if (msg.sender != address(this)) {
            revert TychoFallbackRouter__NotSelf();
        }
        uint256 balanceBefore = IERC20(leg.tokenOut).balanceOf(leg.receiver);

        // Push-payment, so the transfer comes first.
        IERC20(leg.tokenIn).safeTransfer(pamm, leg.amountIn);
        // slither-disable-next-line unused-return
        IPropAMM(pamm)
            .swap(
                leg.tokenIn,
                leg.tokenOut,
                leg.amountIn,
                0,
                leg.receiver,
                block.timestamp
            );

        _requireOutput(leg.tokenOut, leg.receiver, balanceBefore);
    }

    /// @dev The fallback is venue-tagged; a pAMM is not among the kinds, so the venue the primary
    /// slot exists to retry can never also be the rescue. No output measurement here: the
    /// Dispatcher's balance-diff at the receiver is the single source of truth for the leg.
    function _executeFallback(Leg calldata leg, bytes calldata encodedSwap)
        internal
    {
        if (encodedSwap.length == 0) {
            revert TychoFallbackRouter__InvalidSwapLength(encodedSwap.length);
        }

        uint8 venue = uint8(encodedSwap[0]);
        bytes calldata venueData = encodedSwap[1:];

        if (venue == uint8(Venue.UniswapV2)) {
            _swapUniswapV2(leg, venueData);
        } else if (venue == uint8(Venue.UniswapV3)) {
            _swapUniswapV3(leg, venueData);
        } else if (venue == uint8(Venue.UniswapV4)) {
            _swapUniswapV4(leg, venueData);
        } else if (venue == uint8(Venue.Curve)) {
            _swapCurve(leg, venueData);
        } else if (venue == uint8(Venue.FluidV1)) {
            _swapFluidV1(leg, venueData);
        } else {
            revert TychoFallbackRouter__UnknownVenue(venue);
        }
    }

    /// @dev Reverts on zero delivered, so a pAMM that fills with nothing still falls through to
    /// the fallback.
    function _requireOutput(
        address tokenOut,
        address receiver,
        uint256 balanceBefore
    ) internal view {
        if (IERC20(tokenOut).balanceOf(receiver) <= balanceBefore) {
            revert TychoFallbackRouter__NoOutput();
        }
    }

    /// @notice Sets the gas forwarded to the pAMM try.
    function setPammGasCap(uint256 newCap)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (newCap == 0) {
            revert TychoFallbackRouter__ZeroGasCap();
        }
        emit PammGasCapUpdated(pammGasCap, newCap);
        pammGasCap = newCap;
    }

    /// @notice Sends out a balance a Curve exchange rounded into this contract.
    function rescue(address token, address receiver, uint256 amount)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (receiver == address(0)) {
            revert TychoFallbackRouter__AddressZero();
        }
        emit Rescued(token, receiver, amount);
        IERC20(token).safeTransfer(receiver, amount);
    }

    /// @dev Venue data: `[pair: 20][feeBps: 1]`. The pair prices nothing, so the output amount
    /// comes from the reserves.
    function _swapUniswapV2(Leg calldata leg, bytes calldata data) internal {
        if (data.length != 21) {
            revert TychoFallbackRouter__InvalidSwapLength(data.length);
        }
        IUniswapV2Pair pair = IUniswapV2Pair(address(bytes20(data[0:20])));
        uint256 feeBps = uint8(data[20]);
        if (feeBps > 30) {
            revert TychoFallbackRouter__InvalidUniswapV2Fee(feeBps);
        }

        bool zeroForOne = leg.tokenIn < leg.tokenOut;
        // slither-disable-next-line unused-return
        (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
        uint256 calculatedAmount = UniswapV2Math.getAmountOut(
            leg.amountIn,
            zeroForOne ? reserve0 : reserve1,
            zeroForOne ? reserve1 : reserve0,
            feeBps
        );

        IERC20(leg.tokenIn).safeTransfer(address(pair), leg.amountIn);
        if (zeroForOne) {
            pair.swap(0, calculatedAmount, leg.receiver, "");
        } else {
            pair.swap(calculatedAmount, 0, leg.receiver, "");
        }
    }

    /// @dev Venue data: `[pool: 20]`.
    function _swapUniswapV3(Leg calldata leg, bytes calldata data) internal {
        if (data.length != 20) {
            revert TychoFallbackRouter__InvalidSwapLength(data.length);
        }
        address pool = address(bytes20(data[0:20]));
        bool zeroForOne = leg.tokenIn < leg.tokenOut;

        _setCallbackContext(pool, leg.tokenIn, leg.amountIn);
        // slither-disable-next-line unused-return
        IUniswapV3Pool(pool)
            .swap(
                leg.receiver,
                zeroForOne,
                int256(leg.amountIn),
                zeroForOne
                    ? TickMath.MIN_SQRT_PRICE + 1
                    : TickMath.MAX_SQRT_PRICE - 1,
                ""
            );
        _clearCallbackContext();
    }

    /// @dev Venue data: `[fee: 3][tickSpacing: 3][hook: 20][hookData: rest]`. One pool, never a
    /// path: the currencies come from the sort order of `tokenIn` and `tokenOut`.
    function _swapUniswapV4(Leg calldata leg, bytes calldata data) internal {
        if (data.length < 26) {
            revert TychoFallbackRouter__InvalidSwapLength(data.length);
        }

        UniswapV4Swap memory v4Swap = UniswapV4Swap({
            leg: leg,
            fee: uint24(bytes3(data[0:3])),
            tickSpacing: int24(uint24(bytes3(data[3:6]))),
            hook: address(bytes20(data[6:26])),
            hookData: data[26:]
        });

        // slither-disable-next-line unused-return
        poolManager.unlock(abi.encode(v4Swap));
    }

    /// @dev Venue data: `[pool: 20][poolType: 1][i: 1][j: 1]`. Curve pays the caller, so this
    /// forwards to `receiver`.
    function _swapCurve(Leg calldata leg, bytes calldata data) internal {
        if (data.length != 23) {
            revert TychoFallbackRouter__InvalidSwapLength(data.length);
        }
        address pool = address(bytes20(data[0:20]));
        uint8 poolType = uint8(data[20]);
        uint256 i = uint8(data[21]);
        uint256 j = uint8(data[22]);

        uint256 balanceBefore = IERC20(leg.tokenOut).balanceOf(address(this));

        IERC20(leg.tokenIn).forceApprove(pool, leg.amountIn);
        if (poolType == 1 || poolType == 10) {
            // stable and stable_ng
            ICurveStablePool(pool)
                .exchange(
                    int128(uint128(i)), int128(uint128(j)), leg.amountIn, 0
                );
        } else {
            // crypto or llamma
            ICurveCryptoPool(pool).exchange(i, j, leg.amountIn, 0);
        }
        IERC20(leg.tokenIn).forceApprove(pool, 0);

        uint256 received =
            IERC20(leg.tokenOut).balanceOf(address(this)) - balanceBefore;
        IERC20(leg.tokenOut).safeTransfer(leg.receiver, received);
    }

    /// @dev Venue data: `[dex: 20][zero2one: 1]`. `zero2one` is the dex's token order, not the
    /// address sort order, so it cannot be derived.
    function _swapFluidV1(Leg calldata leg, bytes calldata data) internal {
        if (data.length != 21) {
            revert TychoFallbackRouter__InvalidSwapLength(data.length);
        }
        address dex = address(bytes20(data[0:20]));
        bool zero2one = uint8(data[20]) > 0;

        _setCallbackContext(dex, leg.tokenIn, leg.amountIn);
        // slither-disable-next-line unused-return
        IFluidV1Dex(dex)
            .swapInWithCallback(zero2one, leg.amountIn, 0, leg.receiver);
        _clearCallbackContext();
    }

    /// @notice Pays a Uniswap V3 pool.
    /// @dev The pool's deltas are ignored; token and amount come from the callback context.
    function uniswapV3SwapCallback(
        int256, /* amount0Delta */
        int256, /* amount1Delta */
        bytes calldata /* data */
    )
        external
    {
        (address tokenIn, uint256 amountIn) = _consumeCallbackContext();
        IERC20(tokenIn).safeTransfer(msg.sender, amountIn);
    }

    /// @notice Pays the Fluid liquidity layer. The requested token must match the callback
    /// context -- a mismatch means the encoded `zero2one` contradicts the leg -- but the paid
    /// amount comes from the context, never from the dex.
    function dexCallback(
        address token_,
        uint256 /* amount_ */
    )
        external
    {
        (address tokenIn, uint256 amountIn) = _consumeCallbackContext();
        if (token_ != tokenIn) {
            revert TychoFallbackRouter__CallbackTokenMismatch(token_, tokenIn);
        }
        IERC20(tokenIn).safeTransfer(fluidLiquidity, amountIn);
    }

    function unlockCallback(bytes calldata data)
        external
        returns (bytes memory)
    {
        if (msg.sender != address(poolManager)) {
            revert TychoFallbackRouter__NotPoolManager();
        }
        UniswapV4Swap memory v4Swap = abi.decode(data, (UniswapV4Swap));
        Leg memory leg = v4Swap.leg;
        bool zeroForOne = leg.tokenIn < leg.tokenOut;

        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(zeroForOne ? leg.tokenIn : leg.tokenOut),
            currency1: Currency.wrap(zeroForOne ? leg.tokenOut : leg.tokenIn),
            fee: v4Swap.fee,
            tickSpacing: v4Swap.tickSpacing,
            hooks: IHooks(v4Swap.hook)
        });

        poolManager.sync(Currency.wrap(leg.tokenIn));
        IERC20(leg.tokenIn).safeTransfer(address(poolManager), leg.amountIn);
        // slither-disable-next-line unused-return
        poolManager.settle();

        BalanceDelta delta = poolManager.swap(
            key,
            SwapParams(
                zeroForOne,
                -int256(leg.amountIn),
                zeroForOne
                    ? TickMath.MIN_SQRT_PRICE + 1
                    : TickMath.MAX_SQRT_PRICE - 1
            ),
            v4Swap.hookData
        );

        int128 amountOut = zeroForOne ? delta.amount1() : delta.amount0();
        // A negative delta (hostile hook) wraps to an amount `take` cannot pay, so it reverts
        // there; a zero delta fails the route-level minAmountOut like any other empty venue.
        poolManager.take(
            Currency.wrap(leg.tokenOut),
            leg.receiver,
            uint256(uint128(amountOut))
        );
        return "";
    }

    function _clearCallbackContext() internal {
        _setCallbackContext(address(0), address(0), 0);
    }

    function _setCallbackContext(address source, address token, uint256 amount)
        internal
    {
        // slither-disable-next-line assembly
        assembly {
            tstore(_CALLBACK_SOURCE_SLOT, source)
            tstore(_CALLBACK_TOKEN_SLOT, token)
            tstore(_CALLBACK_AMOUNT_SLOT, amount)
        }
    }

    /// @dev Clears the context, so one callback cannot pay twice.
    function _consumeCallbackContext()
        internal
        returns (address token, uint256 amount)
    {
        address source;
        // slither-disable-next-line assembly
        assembly {
            source := tload(_CALLBACK_SOURCE_SLOT)
            token := tload(_CALLBACK_TOKEN_SLOT)
            amount := tload(_CALLBACK_AMOUNT_SLOT)
            tstore(_CALLBACK_SOURCE_SLOT, 0)
            tstore(_CALLBACK_TOKEN_SLOT, 0)
            tstore(_CALLBACK_AMOUNT_SLOT, 0)
        }
        // An unset context has source == address(0), which no real sender matches.
        if (msg.sender != source) {
            revert TychoFallbackRouter__InvalidCallback();
        }
    }
}
