// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import {IERC20, ISwapAdapter} from "src/interfaces/ISwapAdapter.sol";

// Integral handles arbirary amounts, but we limit the amount to 10x just in case
uint256 constant RESERVE_LIMIT_FACTOR = 10;

/// @title Integral Swap Adapter
contract IntegralSwapAdapter is ISwapAdapter {
    ITwapFactory immutable factory;

    constructor(address factory_) {
        factory = ITwapFactory(factory_);
    }

    function price(
        bytes32 _poolId,
        IERC20 _sellToken,
        IERC20 _buyToken,
        uint256[] memory _specifiedAmounts
    ) external view override returns (Fraction[] memory _prices) {
        revert NotImplemented("IntegralSwapAdapter.price");
    }

    function swap(
        bytes32 poolId,
        IERC20 sellToken,
        IERC20 buyToken,
        OrderSide side,
        uint256 specifiedAmount
    ) external returns (Trade memory trade) {
        revert NotImplemented("IntegralSwapAdapter.swap");
    }

    function getLimits(bytes32 poolId, IERC20 sellToken, IERC20 buyToken)
        external
        returns (uint256[] memory limits)
    {
        revert NotImplemented("IntegralSwapAdapter.getLimits");
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
