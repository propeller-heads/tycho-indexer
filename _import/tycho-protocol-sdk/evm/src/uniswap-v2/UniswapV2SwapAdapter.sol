// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import {IERC20, ISwapAdapter} from "src/interfaces/ISwapAdapter.sol";

// Uniswap handles arbirary amounts, but we limit the amount to 10x just in case
uint256 constant RESERVE_LIMIT_FACTOR = 10;

contract UniswapV2SwapAdapter is ISwapAdapter {
    IUniswapV2Factory immutable factory;

    constructor(address factory_) {
        factory = IUniswapV2Factory(factory_);
    }

    /// @inheritdoc ISwapAdapter
    function price(
        bytes32 poolId,
        IERC20 sellToken,
        IERC20 buyToken,
        uint256[] memory specifiedAmounts
    ) external view override returns (Fraction[] memory prices) {
        prices = new Fraction[](specifiedAmounts.length);
        IUniswapV2Pair pair = IUniswapV2Pair(address(bytes20(poolId)));
        uint112 r0;
        uint112 r1;
        if (sellToken < buyToken) {
            (r0, r1,) = pair.getReserves();
        } else {
            (r1, r0,) = pair.getReserves();
        }

        for (uint256 i = 0; i < specifiedAmounts.length; i++) {
            prices[i] = getPriceAt(specifiedAmounts[i], r0, r1);
        }
    }

    /// @notice Calculates pool prices for specified amounts
    /// @param amountIn The amount of the token being sold.
    /// @param reserveIn The reserve of the token being sold.
    /// @param reserveOut The reserve of the token being bought.
    /// @return The price as a fraction corresponding to the provided amount.
    function getPriceAt(uint256 amountIn, uint256 reserveIn, uint256 reserveOut)
        internal
        pure
        returns (Fraction memory)
    {
        if (reserveIn == 0 || reserveOut == 0) {
            revert Unavailable("At least one reserve is zero!");
        }
        uint256 amountInWithFee = amountIn * 997;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = (reserveIn * 1000) + amountInWithFee;
        uint256 amountOut = numerator / denominator;
        uint256 newReserveOut = reserveOut - amountOut;
        uint256 newReserveIn = reserveIn + amountIn;
        return Fraction(newReserveOut * 1000, newReserveIn * 997);
    }

    /// @inheritdoc ISwapAdapter
    function swap(
        bytes32 poolId,
        IERC20 sellToken,
        IERC20 buyToken,
        OrderSide side,
        uint256 specifiedAmount
    ) external override returns (Trade memory trade) {
        if (specifiedAmount == 0) {
            return trade;
        }

        IUniswapV2Pair pair = IUniswapV2Pair(address(bytes20(poolId)));
        uint112 r0;
        uint112 r1;
        bool zero2one = sellToken < buyToken;
        if (zero2one) {
            (r0, r1,) = pair.getReserves();
        } else {
            (r1, r0,) = pair.getReserves();
        }
        uint256 gasBefore = gasleft();
        if (side == OrderSide.Sell) {
            trade.calculatedAmount =
                sell(pair, sellToken, zero2one, r0, r1, specifiedAmount);
        } else {
            trade.calculatedAmount =
                buy(pair, sellToken, zero2one, r0, r1, specifiedAmount);
        }
        trade.gasUsed = gasBefore - gasleft();
        trade.price = getPriceAt(specifiedAmount, r0, r1);
    }

    /// @notice Executes a sell order on a given pool.
    /// @param pair The pair to trade on.
    /// @param sellToken The token being sold.
    /// @param zero2one Whether the sell token is token0 or token1.
    /// @param reserveIn The reserve of the token being sold.
    /// @param reserveOut The reserve of the token being bought.
    /// @param amount The amount to be traded.
    /// @return calculatedAmount The amount of tokens received.
    function sell(
        IUniswapV2Pair pair,
        IERC20 sellToken,
        bool zero2one,
        uint112 reserveIn,
        uint112 reserveOut,
        uint256 amount
    ) internal returns (uint256 calculatedAmount) {
        address swapper = msg.sender;
        uint256 amountOut = getAmountOut(amount, reserveIn, reserveOut);

        // TODO: use safeTransferFrom
        sellToken.transferFrom(swapper, address(pair), amount);
        if (zero2one) {
            pair.swap(0, amountOut, swapper, "");
        } else {
            pair.swap(amountOut, 0, swapper, "");
        }
        return amountOut;
    }

    /// @notice Given an input amount of an asset and pair reserves, returns the
    /// maximum output amount of the other asset
    /// @param amountIn The amount of the token being sold.
    /// @param reserveIn The reserve of the token being sold.
    /// @param reserveOut The reserve of the token being bought.
    /// @return amountOut The amount of tokens received.
    function getAmountOut(
        uint256 amountIn,
        uint256 reserveIn,
        uint256 reserveOut
    ) internal pure returns (uint256 amountOut) {
        if (amountIn == 0) {
            return 0;
        }
        if (reserveIn == 0 || reserveOut == 0) {
            revert Unavailable("At least one reserve is zero!");
        }
        uint256 amountInWithFee = amountIn * 997;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = reserveIn * 1000 + amountInWithFee;
        amountOut = numerator / denominator;
    }

    /// @notice Execute a buy order on a given pool.
    /// @param pair The pair to trade on.
    /// @param sellToken The token being sold.
    /// @param zero2one Whether the sell token is token0 or token1.
    /// @param reserveIn The reserve of the token being sold.
    /// @param reserveOut The reserve of the token being bought.
    /// @param amountOut The amount of tokens to be bought.
    /// @return calculatedAmount The amount of tokens sold.
    function buy(
        IUniswapV2Pair pair,
        IERC20 sellToken,
        bool zero2one,
        uint112 reserveIn,
        uint112 reserveOut,
        uint256 amountOut
    ) internal returns (uint256 calculatedAmount) {
        address swapper = msg.sender;
        uint256 amount = getAmountIn(amountOut, reserveIn, reserveOut);

        if (amount == 0) {
            return 0;
        }
        // TODO: use safeTransferFrom
        sellToken.transferFrom(swapper, address(pair), amount);
        if (zero2one) {
            pair.swap(0, amountOut, swapper, "");
        } else {
            pair.swap(amountOut, 0, swapper, "");
        }
        return amount;
    }

    /// @notice Given an output amount of an asset and pair reserves, returns a
    /// required input amount of the other asset
    /// @param amountOut The amount of the token being bought.
    /// @param reserveIn The reserve of the token being sold.
    /// @param reserveOut The reserve of the token being bought.
    function getAmountIn(
        uint256 amountOut,
        uint256 reserveIn,
        uint256 reserveOut
    ) internal pure returns (uint256 amountIn) {
        if (amountOut == 0) {
            return 0;
        }
        if (reserveIn == 0) {
            revert Unavailable("reserveIn is zero");
        }
        if (reserveOut == 0) {
            revert Unavailable("reserveOut is zero");
        }
        uint256 numerator = reserveIn * amountOut * 1000;
        uint256 denominator = (reserveOut - amountOut) * 997;
        amountIn = (numerator / denominator) + 1;
    }

    /// @inheritdoc ISwapAdapter
    function getLimits(bytes32 poolId, IERC20 sellToken, IERC20 buyToken)
        external
        view
        override
        returns (uint256[] memory limits)
    {
        IUniswapV2Pair pair = IUniswapV2Pair(address(bytes20(poolId)));
        limits = new uint256[](2);
        (uint256 r0, uint256 r1,) = pair.getReserves();
        if (sellToken < buyToken) {
            limits[0] = r0 / RESERVE_LIMIT_FACTOR;
            limits[1] = r1 / RESERVE_LIMIT_FACTOR;
        } else {
            limits[0] = r1 / RESERVE_LIMIT_FACTOR;
            limits[1] = r0 / RESERVE_LIMIT_FACTOR;
        }
    }

    /// @inheritdoc ISwapAdapter
    function getCapabilities(bytes32, IERC20, IERC20)
        external
        pure
        override
        returns (Capability[] memory capabilities)
    {
        capabilities = new Capability[](3);
        capabilities[0] = Capability.SellOrder;
        capabilities[1] = Capability.BuyOrder;
        capabilities[2] = Capability.PriceFunction;
    }

    /// @inheritdoc ISwapAdapter
    function getTokens(bytes32 poolId)
        external
        view
        override
        returns (IERC20[] memory tokens)
    {
        tokens = new IERC20[](2);
        IUniswapV2Pair pair = IUniswapV2Pair(address(bytes20(poolId)));
        tokens[0] = IERC20(pair.token0());
        tokens[1] = IERC20(pair.token1());
    }

    /// @inheritdoc ISwapAdapter
    function getPoolIds(uint256 offset, uint256 limit)
        external
        view
        override
        returns (bytes32[] memory ids)
    {
        uint256 endIdx = offset + limit;
        if (endIdx > factory.allPairsLength()) {
            endIdx = factory.allPairsLength();
        }
        ids = new bytes32[](endIdx - offset);
        for (uint256 i = 0; i < ids.length; i++) {
            ids[i] = bytes20(factory.allPairs(offset + i));
        }
    }
}

interface IUniswapV2Pair {
    event Approval(
        address indexed owner, address indexed spender, uint256 value
    );
    event Transfer(address indexed from, address indexed to, uint256 value);

    function name() external pure returns (string memory);
    function symbol() external pure returns (string memory);
    function decimals() external pure returns (uint8);
    function totalSupply() external view returns (uint256);
    function balanceOf(address owner) external view returns (uint256);
    function allowance(address owner, address spender)
        external
        view
        returns (uint256);

    function approve(address spender, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value)
        external
        returns (bool);

    function DOMAIN_SEPARATOR() external view returns (bytes32);
    function PERMIT_TYPEHASH() external pure returns (bytes32);
    function nonces(address owner) external view returns (uint256);

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    event Mint(address indexed sender, uint256 amount0, uint256 amount1);
    event Burn(
        address indexed sender,
        uint256 amount0,
        uint256 amount1,
        address indexed to
    );
    event Swap(
        address indexed sender,
        uint256 amount0In,
        uint256 amount1In,
        uint256 amount0Out,
        uint256 amount1Out,
        address indexed to
    );
    event Sync(uint112 reserve0, uint112 reserve1);

    function MINIMUM_LIQUIDITY() external pure returns (uint256);
    function factory() external view returns (address);
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves()
        external
        view
        returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function price0CumulativeLast() external view returns (uint256);
    function price1CumulativeLast() external view returns (uint256);
    function kLast() external view returns (uint256);

    function mint(address to) external returns (uint256 liquidity);
    function burn(address to)
        external
        returns (uint256 amount0, uint256 amount1);
    function swap(
        uint256 amount0Out,
        uint256 amount1Out,
        address to,
        bytes calldata data
    ) external;
    function skim(address to) external;
    function sync() external;

    function initialize(address, address) external;
}

interface IUniswapV2Factory {
    event PairCreated(
        address indexed token0, address indexed token1, address pair, uint256
    );

    function feeTo() external view returns (address);
    function feeToSetter() external view returns (address);

    function getPair(address tokenA, address tokenB)
        external
        view
        returns (address pair);
    function allPairs(uint256) external view returns (address pair);
    function allPairsLength() external view returns (uint256);

    function createPair(address tokenA, address tokenB)
        external
        returns (address pair);

    function setFeeTo(address) external;
    function setFeeToSetter(address) external;
}
