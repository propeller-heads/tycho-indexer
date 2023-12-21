// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import "src/interfaces/ISwapAdapterTypes.sol";
import "src/libraries/FractionMath.sol";
import "src/integral/IntegralSwapAdapterFix.sol";

contract IntegralSwapAdapterTest is Test, ISwapAdapterTypes {
    using FractionMath for Fraction;

    IntegralSwapAdapter adapter;
    IERC20 constant WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IERC20 constant USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    address constant USDC_WETH_PAIR = 0x2fe16Dd18bba26e457B7dD2080d5674312b026a2;
    address constant relayerAddress = 0xd17b3c9784510E33cD5B87b490E79253BcD81e2E;

    uint256 constant TEST_ITERATIONS = 100;

    function setUp() public {
        uint256 forkBlock = 18835309;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        adapter = new IntegralSwapAdapter(relayerAddress);

        vm.label(address(WETH), "WETH");
        vm.label(address(USDC), "USDC");
        vm.label(address(USDC_WETH_PAIR), "USDC_WETH_PAIR");

    }

}
