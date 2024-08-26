// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "openzeppelin-contracts/contracts/interfaces/IERC20.sol";
import "./Constants.sol";

contract SwapExecutorTest is Test, Constants {
    function twoTokens(address token0, address token1)
        internal
        pure
        returns (IERC20[] memory tokens)
    {
        tokens = new IERC20[](2);
        tokens[0] = IERC20(token0);
        tokens[1] = IERC20(token1);
    }
}
