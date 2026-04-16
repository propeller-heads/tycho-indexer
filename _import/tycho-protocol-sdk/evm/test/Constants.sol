// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract Constants {
    address executor = address(1239501235123412541234); //executor=us || cowswap
    address admin = address(12395012351212343412541234); //admin=us
    address bob = address(123); //bob=someone!=us

    // tokens
    address WETH_ADDR = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address USDT_ADDR = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address USDC_ADDR = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address DAI_ADDR = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address WBTC_ADDR = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;
    address LDO_ADDR = 0x5A98FcBEA516Cf06857215779Fd812CA3beF1B32;
    address CRV_ADDR = 0xD533a949740bb3306d119CC777fa900bA034cd52;

    // balancer
    address balancerVault = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;
    bytes32 DAI_USDC_USDT_balancer = bytes32(
        0x06df3b2bbb68adc8b0e302443692037ed9f91b42000000000000000000000063
    );
}
