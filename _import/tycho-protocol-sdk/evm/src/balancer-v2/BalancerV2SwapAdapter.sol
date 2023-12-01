// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import {IERC20, ISwapAdapter} from "src/interfaces/ISwapAdapter.sol";

interface IVault {
    function getPoolTokens(bytes32 poolId)
        external
        view
        returns (
            IERC20[] memory tokens,
            uint256[] memory balances,
            uint256 lastChangeBlock
        );

    function swap(
        SingleSwap memory singleSwap,
        FundManagement memory funds,
        uint256 limit,
        uint256 deadline
    ) external payable returns (uint256);

    function queryBatchSwap(
        SwapKind kind,
        BatchSwapStep[] memory swaps,
        IAsset[] memory assets,
        FundManagement memory funds
    ) external returns (int256[] memory assetDeltas);

    struct SingleSwap {
        bytes32 poolId;
        SwapKind kind;
        IAsset assetIn;
        IAsset assetOut;
        uint256 amount;
        bytes userData;
    }

    struct BatchSwapStep {
        bytes32 poolId;
        uint256 assetInIndex;
        uint256 assetOutIndex;
        uint256 amount;
        bytes userData;
    }

    struct FundManagement {
        address sender;
        bool fromInternalBalance;
        address payable recipient;
        bool toInternalBalance;
    }

    enum SwapKind { GIVEN_IN, GIVEN_OUT }
}

interface IAsset is IERC20 {
}

contract BalancerV2SwapAdapter is ISwapAdapter {
    IVault immutable vault;

    constructor(address vault_) {
        vault = IVault(vault_);
    }

    function price(
        bytes32 pairId,
        IERC20 sellToken,
        IERC20 buyToken,
        uint256[] memory sellAmounts
    ) external view override returns (Fraction[] memory prices) {
        revert NotImplemented("BalancerV2SwapAdapter.price");
    }

    function getPriceAt(uint256 amountIn, uint256 reserveIn, uint256 reserveOut)
        internal
        pure
        returns (Fraction memory)
    {
        revert NotImplemented("BalancerV2SwapAdapter.getPriceAt");
    }

    function swap(
        bytes32 pairId,
        IERC20 sellToken,
        IERC20 buyToken,
        SwapSide side,
        uint256 specifiedAmount
    ) external override returns (Trade memory trade) {
        revert NotImplemented("BalancerV2SwapAdapter.swap");
    }

    function getLimits(bytes32 pairId, SwapSide side)
        external
        view
        override
        returns (uint256[] memory limits)
    {
        (, limits, ) = vault.getPoolTokens(pairId);
    }

    function getCapabilities(bytes32, IERC20, IERC20)
        external
        pure
        override
        returns (Capability[] memory capabilities)
    {
        capabilities = new Capability[](3);
        capabilities[0] = Capability.SellSide;
        capabilities[1] = Capability.BuySide;
        capabilities[2] = Capability.PriceFunction;
    }

    function getTokens(bytes32 pairId)
        external
        view
        override
        returns (IERC20[] memory tokens)
    {
        revert NotImplemented("BalancerV2SwapAdapter.getTokens");
    }

    /// @dev Balancer V2 does not support listing pools.
    function getPoolIds(uint256 offset, uint256 limit)
        external
        view
        override
        returns (bytes32[] memory ids)
    {
        revert NotImplemented("BalancerV2SwapAdapter.getPoolIds");
    }
}
