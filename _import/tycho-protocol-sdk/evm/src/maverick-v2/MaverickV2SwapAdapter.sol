// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import {ISwapAdapter} from "src/interfaces/ISwapAdapter.sol";
import {
    IERC20,
    SafeERC20
} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title MaverickV2SwapAdapter
/// @notice Adapter for swapping tokens on MaverickV2 pools.
contract MaverickV2SwapAdapter is ISwapAdapter {
    using SafeERC20 for IERC20;

    IMaverickV2Factory public immutable factory;
    IMaverickV2Quoter public immutable quoter;

    /// @notice Constructor to initialize the adapter with factory, quoter, and
    /// WETH addresses.
    /// @param factory_ The address of the MaverickV2 factory.
    /// @param _quoter The address of the MaverickV2 quoter.
    constructor(address factory_, address _quoter) {
        factory = IMaverickV2Factory(factory_);
        quoter = IMaverickV2Quoter(_quoter);
    }

    receive() external payable {}

    /// @inheritdoc ISwapAdapter
    function price(
        bytes32 poolId,
        address sellToken,
        address,
        uint256[] memory specifiedAmounts
    ) external override returns (Fraction[] memory calculatedPrices) {
        calculatedPrices = new Fraction[](specifiedAmounts.length);

        IMaverickV2Pool pool = IMaverickV2Pool(address(bytes20(poolId)));

        for (uint256 i = 0; i < specifiedAmounts.length; i++) {
            calculatedPrices[i] = priceAt(pool, sellToken, specifiedAmounts[i]);
        }
        return calculatedPrices;
    }

    /// @notice Calculate the price of a token at a specified amount.
    /// @param pool The pool to calculate the price for.
    /// @param sellToken The token to calculate the price for.
    /// @param sellAmount The amount of the token to calculate the price for.
    /// @return calculatedPrice The calculated price of the token.
    function priceAt(
        IMaverickV2Pool pool,
        address sellToken,
        uint256 sellAmount
    ) public returns (Fraction memory calculatedPrice) {
        bool isTokenAIn = (sellToken == address(pool.tokenA()));
        int32 tickLimit = isTokenAIn
            ? pool.getState().activeTick + 100
            : pool.getState().activeTick - 100;
        (uint256 amountIn, uint256 amountOut,) = quoter.calculateSwap(
            pool, uint128(sellAmount), isTokenAIn, false, tickLimit
        );

        calculatedPrice = Fraction(amountOut, amountIn);
    }

    /// @inheritdoc ISwapAdapter
    function swap(
        bytes32 poolId,
        address sellToken,
        address,
        OrderSide side,
        uint256 specifiedAmount
    ) external override returns (Trade memory trade) {
        if (specifiedAmount == 0) {
            return trade;
        }

        IMaverickV2Pool pool = IMaverickV2Pool(address(bytes20(poolId)));
        bool isTokenAIn = sellToken == address(pool.tokenA());
        int32 tickLimit = isTokenAIn
            ? pool.getState().activeTick + 100
            : pool.getState().activeTick - 100;
        uint256 gasBefore = gasleft();

        if (side == OrderSide.Buy) {
            trade.calculatedAmount =
                buy(pool, isTokenAIn, tickLimit, specifiedAmount);
            trade.price = priceAt(pool, sellToken, trade.calculatedAmount);
        } else {
            trade.calculatedAmount =
                sell(pool, isTokenAIn, tickLimit, specifiedAmount);
            trade.price = priceAt(pool, sellToken, specifiedAmount);
        }

        trade.gasUsed = gasBefore - gasleft();
        return trade;
    }

    /// @notice Buy tokens from a pool.
    /// @param pool The pool to buy from.
    /// @param isTokenAIn Whether token A is the input token.
    /// @param tickLimit The tick limit for the swap.
    /// @param specifiedAmount The amount of the token to buy.
    /// @return calculatedAmount The amount of the token bought.
    function buy(
        IMaverickV2Pool pool,
        bool isTokenAIn,
        int32 tickLimit,
        uint256 specifiedAmount
    ) internal returns (uint256 calculatedAmount) {
        IMaverickV2Pool.SwapParams memory swapParams = IMaverickV2Pool
            .SwapParams({
            amount: specifiedAmount,
            tokenAIn: isTokenAIn,
            exactOutput: true,
            tickLimit: tickLimit
        });
        // callback data is the sender address
        bytes memory data = abi.encode(msg.sender);
        (uint256 amountIn,) = pool.swap(msg.sender, swapParams, data);
        return amountIn;
    }

    /// @notice Sell tokens to a pool.
    /// @param pool The pool to sell to.
    /// @param isTokenAIn Whether token A is the input token.
    /// @param tickLimit The tick limit for the swap.
    /// @param specifiedAmount The amount of the token to sell.
    /// @return calculatedAmount The amount of the token sold.
    function sell(
        IMaverickV2Pool pool,
        bool isTokenAIn,
        int32 tickLimit,
        uint256 specifiedAmount
    ) internal returns (uint256 calculatedAmount) {
        IMaverickV2Pool.SwapParams memory swapParams = IMaverickV2Pool
            .SwapParams({
            amount: specifiedAmount,
            tokenAIn: isTokenAIn,
            exactOutput: false,
            tickLimit: tickLimit
        });
        // callback data is the sender address
        bytes memory data = abi.encode(msg.sender);
        (, uint256 amountOut) = pool.swap(msg.sender, swapParams, data);
        return amountOut;
    }

    /// @notice MaverickV2SwapCallback is the callback function for MaverickV2
    /// pools.
    /// @param tokenIn The token being swapped.
    /// @param amountIn The amount of the token being swapped.
    /// @param data The data passed to the callback.
    function maverickV2SwapCallback(
        IERC20 tokenIn,
        uint256 amountIn,
        uint256,
        bytes calldata data
    ) external {
        require(
            factory.isFactoryPool(IMaverickV2Pool(msg.sender)), "NotFactoryPool"
        );
        address payer = abi.decode(data, (address));
        tokenIn.safeTransferFrom(payer, msg.sender, amountIn);
    }

    /// @inheritdoc ISwapAdapter
    function getLimits(bytes32 poolId, address sellToken, address buyToken)
        external
        view
        override
        returns (uint256[] memory limits)
    {
        IMaverickV2Pool pool = IMaverickV2Pool(address(bytes20(poolId)));
        IMaverickV2Pool.State memory state = pool.getState();

        limits = new uint256[](2);
        uint256 r0 = state.reserveA;
        uint256 r1 = state.reserveB;
        if (sellToken < buyToken) {
            limits[0] = r0;
            limits[1] = r1;
        } else {
            limits[0] = r1;
            limits[1] = r0;
        }
    }

    /// @inheritdoc ISwapAdapter
    function getCapabilities(bytes32, address, address)
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
        returns (address[] memory tokens)
    {
        tokens = new address[](2);
        IMaverickV2Pool pool = IMaverickV2Pool(address(bytes20(poolId)));
        tokens[0] = address(pool.tokenA());
        tokens[1] = address(pool.tokenB());
    }

    /// @inheritdoc ISwapAdapter
    function getPoolIds(uint256 offset, uint256 limit)
        external
        view
        override
        returns (bytes32[] memory ids)
    {
        IMaverickV2Pool[] memory pools = factory.lookup(offset, offset + limit);
        ids = new bytes32[](pools.length);
        for (uint256 i = 0; i < pools.length; i++) {
            ids[i] = bytes20((address(pools[i])));
        }
    }
}

interface IMaverickV2Pool {
    struct SwapParams {
        uint256 amount;
        bool tokenAIn;
        bool exactOutput;
        int32 tickLimit;
    }

    struct State {
        uint128 reserveA;
        uint128 reserveB;
        int64 lastTwaD8;
        int64 lastLogPriceD8;
        uint40 lastTimestamp;
        int32 activeTick;
        bool isLocked;
        uint32 binCounter;
        uint8 protocolFeeRatioD3;
    }

    function fee(bool tokenAIn) external view returns (uint256);
    function tokenA() external view returns (IERC20);
    function tokenB() external view returns (IERC20);
    function factory() external view returns (IMaverickV2Factory);
    function getState() external view returns (State memory);
    function swap(
        address recipient,
        SwapParams memory params,
        bytes calldata data
    ) external returns (uint256 amountIn, uint256 amountOut);
}

interface IMaverickV2Factory {
    function isFactoryPool(IMaverickV2Pool pool) external view returns (bool);

    function lookup(uint256 startIndex, uint256 endIndex)
        external
        view
        returns (IMaverickV2Pool[] memory pools);
}

interface IWETH9 is IERC20 {
    /// @notice Deposit ether to get wrapped ether
    function deposit() external payable;

    /// @notice Withdraw wrapped ether to get ether
    function withdraw(uint256) external;
}

interface IMaverickV2Quoter {
    function calculateSwap(
        IMaverickV2Pool pool,
        uint128 amount,
        bool tokenAIn,
        bool exactOutput,
        int32 tickLimit
    )
        external
        returns (uint256 amountIn, uint256 amountOut, uint256 gasEstimate);
}
