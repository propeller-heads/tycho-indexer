// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.26;

// Mock for the UniswapV2Pool contract, it is expected to have malicious behavior
contract MockUniswapV2Pool {
    address public token0;
    address public token1;

    constructor(address _tokenA, address _tokenB) {
        token0 = _tokenA < _tokenB ? _tokenA : _tokenB;
        token1 = _tokenA < _tokenB ? _tokenB : _tokenA;
    }
}
