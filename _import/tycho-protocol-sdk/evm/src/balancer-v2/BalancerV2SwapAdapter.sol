// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import {IERC20, ISwapAdapter} from "interfaces/ISwapAdapter.sol";

contract BalancerV2SwapAdapter is ISwapAdapter {

    constructor() {
    }

    function getPairReserves(
        bytes32 pairId,
        IERC20 sellToken,
        IERC20 buyToken
    ) internal view returns (uint112 r0, uint112 r1) {
        revert NotImplemented("BalancerV2SwapAdapter.getPairReserves");
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
        revert NotImplemented("BalancerV2SwapAdapter.getLimits");
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

    function getPoolIds(uint256 offset, uint256 limit)
        external
        view
        override
        returns (bytes32[] memory ids)
    {
        revert NotImplemented("BalancerV2SwapAdapter.getPoolIds");
    }
}
