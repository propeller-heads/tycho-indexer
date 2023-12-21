// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import {IERC20, ISwapAdapter} from "src/interfaces/ISwapAdapter.sol";

/// @dev Integral submitted deadline of 3600 seconds (1 hour) to Paraswap, but it is not strictly necessary to be this long
/// as the contract allows less durations, we use 1000 seconds (15 minutes) as a deadline
uint256 constant SWAP_DEADLINE_SEC = 1000;

/// @title Integral Swap Adapter
contract IntegralSwapAdapter is ISwapAdapter {
    ITwapRelayer immutable relayer;

    constructor(address relayer_) {
        relayer = ITwapRelayer(relayer_);
    }

    /// @inheritdoc ISwapAdapter
    function price(
        bytes32 _poolId,
        IERC20 _sellToken,
        IERC20 _buyToken,
        uint256[] memory _specifiedAmounts
    ) external view override returns (Fraction[] memory _prices) {
        _prices = new Fraction[](_specifiedAmounts.length);
        ITwapPair pair = ITwapPair(address(bytes20(_poolId)));
        uint112 r0;
        uint112 r1;
        if (address(_sellToken) == pair.token0()) { // sell
            (r0, r1) = pair.getReserves();
        } else { // buy
            (r1, r0) = pair.getReserves();
        }

        for (uint256 i = 0; i < _specifiedAmounts.length; i++) {
            _prices[i] = getPriceAt(_specifiedAmounts[i], r0, r1, pair);
        }
    }

    /// @inheritdoc ISwapAdapter
    function swap(
        bytes32 poolId,
        IERC20 sellToken,
        IERC20 buyToken,
        OrderSide side,
        uint256 specifiedAmount
    ) external returns (Trade memory trade) {
        if (specifiedAmount == 0) {
            return trade;
        }

        ITwapPair pair = ITwapPair(address(bytes20(poolId)));
        uint112 r0;
        uint112 r1;
        if (address(sellToken) == pair.token0()) {
            (r0, r1) = pair.getReserves();
        } else {
            (r1, r0) = pair.getReserves();
        }
        uint256 gasBefore = gasleft();
        if (side == OrderSide.Sell) { // sell
            trade.calculatedAmount =
                sell(address(sellToken), address(buyToken), specifiedAmount);
        } else { // buy
            trade.calculatedAmount =
                buy(address(sellToken), address(buyToken), specifiedAmount);
        }
        trade.gasUsed = gasBefore - gasleft();
        trade.price = getPriceAt(specifiedAmount, r0, r1, pair);
    }

    /// @inheritdoc ISwapAdapter
    function getLimits(bytes32 poolId, IERC20 sellToken, IERC20 buyToken)
        external
        view
        override
        returns (uint256[] memory limits)
    {
        (
            uint256 price_,
            uint256 fee,
            uint256 limitMin0,
            uint256 limitMax0,
            uint256 limitMin1,
            uint256 limitMax1
        ) = relayer.getPoolState(address(sellToken), address(buyToken));

        limits = new uint256[](4);
        limits[0] = limitMax0;
        limits[1] = limitMax1;
        limits[2] = limitMin0;
        limits[3] = limitMin1;
    }

    /// @inheritdoc ISwapAdapter
    function getCapabilities(bytes32 poolId, IERC20 sellToken, IERC20 buyToken)
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
        ITwapPair pair = ITwapPair(address(bytes20(poolId)));
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
        ITwapFactory factory = ITwapFactory(relayer.factory());
        uint256 endIdx = offset + limit;
        if (endIdx > factory.allPairsLength()) {
            endIdx = factory.allPairsLength();
        }
        ids = new bytes32[](endIdx - offset);
        for (uint256 i = 0; i < ids.length; i++) {
            ids[i] = bytes20(factory.allPairs(offset + i));
        }
    }

    /// @notice Calculates pool prices after trade for specified amounts
    /// @param amountIn The amount of the token being sold.
    /// @param reserveIn The reserve of the token being sold.
    /// @param reserveOut The reserve of the token being bought.
    /// @param pair (ITwapPair) The pair where to execute the swap in.
    /// @dev Although Integral declares in its Docs that the fee is 1 BP(0.01%, 0.0001 multiplier),
    /// it can be changed at any time by calling a function of the contract by its owner or operator,
    /// therefore it is obtained dynamically to ensure this function output remains reliable over time
    /// @return The price as a fraction corresponding to the provided amount.
    function getPriceAt(uint256 amountIn, uint256 reserveIn, uint256 reserveOut, ITwapPair pair)
        internal
        view
        returns (Fraction memory)
    {
        if (reserveIn == 0 || reserveOut == 0) {
            revert Unavailable("At least one reserve is zero!");
        }
        uint256 feeBP = relayer.swapFee(address(pair));

        uint256 amountInWithFee = amountIn - ( (amountIn * feeBP) / 10**18 );
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = (reserveIn * 1000) + amountInWithFee;
        uint256 amountOut = numerator / denominator;
        uint256 newReserveOut = reserveOut - amountOut;
        uint256 newReserveIn = reserveIn + amountIn;

        return Fraction(
            newReserveOut * 1000, 
            newReserveIn - ( (newReserveIn * feeBP) / 10**18 )
        );
    }

    /// @notice Executes a sell order on a given pool.
    /// @param sellToken The address of the token being sold.
    /// @param buyToken The address of the token being bought.
    /// @param amount The amount to be traded.
    /// @return uint256 The amount of tokens received.
    function sell(
        address sellToken,
        address buyToken,
        uint256 amount
    ) internal returns (uint256) {
        address swapper = msg.sender;
        uint256 amountOut = relayer.quoteSell(sellToken, buyToken, amount);

        if (amountOut == 0) {
            revert Unavailable("AmountOut is zero!");
        }

        IERC20(sellToken).transferFrom(msg.sender, address(this), amount);
        IERC20(sellToken).approve(address(relayer), amount);

        relayer.sell(ITwapRelayer.SellParams({
            tokenIn: sellToken,
            tokenOut: buyToken,
            wrapUnwrap: false,
            to: swapper,
            submitDeadline: uint32(block.timestamp + SWAP_DEADLINE_SEC),
            amountIn: amount,
            amountOutMin: amountOut
        }));

        return amountOut;
    }

    /// @notice Executes a buy order on a given pool.
    /// @param sellToken The address of the token being sold.
    /// @param buyToken The address of the token being bought.
    /// @param amountBought The amount of buyToken tokens to buy.
    /// @return uint256 The amount of tokens received.
    function buy(
        address sellToken,
        address buyToken,
        uint256 amountBought
    ) internal returns (uint256) {
        address swapper = msg.sender;
        uint256 amountIn = relayer.quoteBuy(sellToken, buyToken, amountBought);

        if (amountIn == 0) {
            revert Unavailable("AmountIn is zero!");
        }

        IERC20(sellToken).transferFrom(msg.sender, address(this), amountIn);
        IERC20(sellToken).approve(address(relayer), amountIn);

        relayer.buy(ITwapRelayer.BuyParams({
            tokenIn: sellToken,
            tokenOut: buyToken,
            wrapUnwrap: false,
            to: swapper,
            submitDeadline: uint32(block.timestamp + SWAP_DEADLINE_SEC),
            amountInMax: amountIn,
            amountOut: amountBought
        }));

        return amountIn;
    }
}

interface ITwapRelayer {
    event OwnerSet(address owner);
    event RebalancerSet(address rebalancer);
    event DelaySet(address delay);
    event PairEnabledSet(address pair, bool enabled);
    event SwapFeeSet(address pair, uint256 fee);
    event TwapIntervalSet(address pair, uint32 interval);
    event EthTransferGasCostSet(uint256 gasCost);
    event ExecutionGasLimitSet(uint256 limit);
    event TokenLimitMinSet(address token, uint256 limit);
    event TokenLimitMaxMultiplierSet(address token, uint256 limit);
    event ToleranceSet(address pair, uint16 tolerance);
    event Approve(address token, address to, uint256 amount);
    event Withdraw(address token, address to, uint256 amount);
    event Sell(
        address indexed sender,
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 amountOut,
        uint256 amountOutMin,
        bool wrapUnwrap,
        uint256 fee,
        address indexed to,
        address orderContract,
        uint256 indexed orderId
    );
    event Buy(
        address indexed sender,
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 amountInMax,
        uint256 amountOut,
        bool wrapUnwrap,
        uint256 fee,
        address indexed to,
        address orderContract,
        uint256 indexed orderId
    );
    event RebalanceSellWithDelay(
        address indexed sender,
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 indexed delayOrderId
    );
    event RebalanceSellWithOneInch(address indexed oneInchRouter, uint256 gas, bytes data);
    event OneInchRouterWhitelisted(address indexed oneInchRouter, bool whitelisted);

    function factory() external pure returns (address);

    function delay() external pure returns (address);

    function weth() external pure returns (address);

    function owner() external view returns (address);

    function rebalancer() external view returns (address);

    function isOneInchRouterWhitelisted(address oneInchRouter) external view returns (bool);

    function setOwner(address _owner) external;

    function swapFee(address pair) external view returns (uint256);

    function setSwapFee(address pair, uint256 fee) external;

    function twapInterval(address pair) external pure returns (uint32);

    function isPairEnabled(address pair) external view returns (bool);

    function setPairEnabled(address pair, bool enabled) external;

    function ethTransferGasCost() external pure returns (uint256);

    function executionGasLimit() external pure returns (uint256);

    function tokenLimitMin(address token) external pure returns (uint256);

    function tokenLimitMaxMultiplier(address token) external pure returns (uint256);

    function tolerance(address pair) external pure returns (uint16);

    function setRebalancer(address _rebalancer) external;

    function whitelistOneInchRouter(address oneInchRouter, bool whitelisted) external;

    function getTolerance(address pair) external pure returns (uint16);

    function getTokenLimitMin(address token) external pure returns (uint256);

    function getTokenLimitMaxMultiplier(address token) external pure returns (uint256);

    function getTwapInterval(address pair) external pure returns (uint32);

    struct SellParams {
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint256 amountOutMin;
        bool wrapUnwrap;
        address to;
        uint32 submitDeadline;
    }

    function sell(SellParams memory sellParams) external payable returns (uint256 orderId);

    struct BuyParams {
        address tokenIn;
        address tokenOut;
        uint256 amountInMax;
        uint256 amountOut;
        bool wrapUnwrap;
        address to;
        uint32 submitDeadline;
    }

    function buy(BuyParams memory buyParams) external payable returns (uint256 orderId);

    function getPriceByPairAddress(address pair, bool inverted)
        external
        view
        returns (
            uint8 xDecimals,
            uint8 yDecimals,
            uint256 price
        );

    function getPriceByTokenAddresses(address tokenIn, address tokenOut) external view returns (uint256 price);

    function getPoolState(address token0, address token1)
        external
        view
        returns (
            uint256 price,
            uint256 fee,
            uint256 limitMin0,
            uint256 limitMax0,
            uint256 limitMin1,
            uint256 limitMax1
        );

    function quoteSell(
        address tokenIn,
        address tokenOut,
        uint256 amountIn
    ) external view returns (uint256 amountOut);

    function quoteBuy(
        address tokenIn,
        address tokenOut,
        uint256 amountOut
    ) external view returns (uint256 amountIn);

    function approve(
        address token,
        uint256 amount,
        address to
    ) external;

    function withdraw(
        address token,
        uint256 amount,
        address to
    ) external;

    function rebalanceSellWithDelay(
        address tokenIn,
        address tokenOut,
        uint256 amountIn
    ) external;

    function rebalanceSellWithOneInch(
        address tokenIn,
        uint256 amountIn,
        address oneInchRouter,
        uint256 _gas,
        bytes calldata data
    ) external;
}

interface ITwapFactory {
    event PairCreated(address indexed token0, address indexed token1, address pair, uint256);
    event OwnerSet(address owner);

    function owner() external view returns (address);

    function getPair(address tokenA, address tokenB) external view returns (address pair);

    function allPairs(uint256) external view returns (address pair);

    function allPairsLength() external view returns (uint256);

    function createPair(
        address tokenA,
        address tokenB,
        address oracle,
        address trader
    ) external returns (address pair);

    function setOwner(address) external;

    function setMintFee(
        address tokenA,
        address tokenB,
        uint256 fee
    ) external;

    function setBurnFee(
        address tokenA,
        address tokenB,
        uint256 fee
    ) external;

    function setSwapFee(
        address tokenA,
        address tokenB,
        uint256 fee
    ) external;

    function setOracle(
        address tokenA,
        address tokenB,
        address oracle
    ) external;

    function setTrader(
        address tokenA,
        address tokenB,
        address trader
    ) external;

    function collect(
        address tokenA,
        address tokenB,
        address to
    ) external;

    function withdraw(
        address tokenA,
        address tokenB,
        uint256 amount,
        address to
    ) external;
}

interface ITwapERC20 is IERC20 {
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

    function increaseAllowance(address spender, uint256 addedValue) external returns (bool);

    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool);
}

interface IReserves {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1);

    function getFees() external view returns (uint256 fee0, uint256 fee1);
}

interface ITwapPair is ITwapERC20, IReserves {
    event Mint(address indexed sender, uint256 amount0In, uint256 amount1In, uint256 liquidityOut, address indexed to);
    event Burn(address indexed sender, uint256 amount0Out, uint256 amount1Out, uint256 liquidityIn, address indexed to);
    event Swap(
        address indexed sender,
        uint256 amount0In,
        uint256 amount1In,
        uint256 amount0Out,
        uint256 amount1Out,
        address indexed to
    );
    event SetMintFee(uint256 fee);
    event SetBurnFee(uint256 fee);
    event SetSwapFee(uint256 fee);
    event SetOracle(address account);
    event SetTrader(address trader);

    function MINIMUM_LIQUIDITY() external pure returns (uint256);

    function factory() external view returns (address);

    function token0() external view returns (address);

    function token1() external view returns (address);

    function oracle() external view returns (address);

    function trader() external view returns (address);

    function mintFee() external view returns (uint256);

    function setMintFee(uint256 fee) external;

    function mint(address to) external returns (uint256 liquidity);

    function burnFee() external view returns (uint256);

    function setBurnFee(uint256 fee) external;

    function burn(address to) external returns (uint256 amount0, uint256 amount1);

    function swapFee() external view returns (uint256);

    function setSwapFee(uint256 fee) external;

    function setOracle(address account) external;

    function setTrader(address account) external;

    function collect(address to) external;

    function swap(
        uint256 amount0Out,
        uint256 amount1Out,
        address to,
        bytes calldata data
    ) external;

    function sync() external;

    function initialize(
        address _token0,
        address _token1,
        address _oracle,
        address _trader
    ) external;

    function getSwapAmount0In(uint256 amount1Out, bytes calldata data) external view returns (uint256 swapAmount0In);

    function getSwapAmount1In(uint256 amount0Out, bytes calldata data) external view returns (uint256 swapAmount1In);

    function getSwapAmount0Out(uint256 amount1In, bytes calldata data) external view returns (uint256 swapAmount0Out);

    function getSwapAmount1Out(uint256 amount0In, bytes calldata data) external view returns (uint256 swapAmount1Out);

    function getDepositAmount0In(uint256 amount0, bytes calldata data) external view returns (uint256 depositAmount0In);

    function getDepositAmount1In(uint256 amount1, bytes calldata data) external view returns (uint256 depositAmount1In);
}
