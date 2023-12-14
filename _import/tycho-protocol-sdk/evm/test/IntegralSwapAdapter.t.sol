// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "src/interfaces/ISwapAdapterTypes.sol";
import "src/libraries/FractionMath.sol";

/// @title TemplateSwapAdapterTest
/// @dev This is a template for a swap adapter test.
/// Test all functions that are implemented in your swap adapter, the two test included here are just an example.
/// Feel free to use UniswapV2SwapAdapterTest and BalancerV2SwapAdapterTest as a reference.
contract TemplateSwapAdapterTest is Test, ISwapAdapterTypes {
    using FractionMath for Fraction;

    function testPriceFuzz(uint256 amount0, uint256 amount1) public {}

    function testSwapFuzz(uint256 specifiedAmount) public {}
}
