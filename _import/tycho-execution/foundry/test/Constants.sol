// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "forge-std/Test.sol";

contract BaseConstants {
    address BASE_USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    address BASE_MAG7 = 0x9E6A46f294bB67c20F1D1E7AfB0bBEf614403B55;

    // Uniswap v2
    address USDC_MAG7_POOL = 0x739c2431670A12E2cF8e11E3603eB96e6728a789;
}

contract Constants is Test, BaseConstants {
    address ADMIN = makeAddr("admin"); //admin=us
    address BOB = makeAddr("bob"); //bob=someone!=us
    address FUND_RESCUER = makeAddr("fundRescuer");
    address FEE_SETTER = makeAddr("feeSetter");
    address FEE_RECEIVER = makeAddr("feeReceiver");
    address EXECUTOR_SETTER = makeAddr("executorSetter");
    address ALICE = 0xcd09f75E2BF2A4d11F3AB23f1389FcC1621c0cc2;
    uint256 ALICE_PK =
        0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234;

    // Dummy contracts
    address DUMMY = makeAddr("dummy");
    address DUMMY2 = makeAddr("dummy2");
    address DUMMY3 = makeAddr("dummy3");
    address PAUSER = makeAddr("pauser");
    address UNPAUSER = makeAddr("unpauser");

    // Assets
    address WETH_ADDR = address(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    address DAI_ADDR = address(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    address BAL_ADDR = address(0xba100000625a3754423978a60c9317c58a424e3D);
    address USDC_ADDR = address(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    address WBTC_ADDR = address(0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599);
    address INCH_ADDR = address(0x111111111117dC0aa78b770fA6A738034120C302);
    address USDE_ADDR = address(0x4c9EDD5852cd905f086C759E8383e09bff1E68B3);
    address USDT_ADDR = address(0xdAC17F958D2ee523a2206206994597C13D831ec7);
    address PEPE_ADDR = address(0x6982508145454Ce325dDbE47a25d4ec3d2311933);

    // Uniswap v2
    address WETH_DAI_POOL = 0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11;
    address DAI_USDC_POOL = 0xAE461cA67B15dc8dc81CE7615e0320dA1A9aB8D5;
    address WETH_WBTC_POOL = 0xBb2b8038a1640196FbE3e38816F3e67Cba72D940;
    address USDC_WBTC_POOL = 0x004375Dff511095CC5A197A54140a24eFEF3A416;
    address USDC_WETH_USV2 = 0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc;

    // Sushiswap v2
    address SUSHISWAP_WBTC_WETH_POOL =
        0xCEfF51756c56CeFFCA006cD410B03FFC46dd3a58;

    // Pancakeswap v2
    address PANCAKESWAP_WBTC_WETH_POOL =
        0x4AB6702B3Ed3877e9b1f203f90cbEF13d663B0e8;

    // Factories
    address USV3_FACTORY_ETHEREUM = 0x1F98431c8aD98523631AE4a59f267346ea31F984;
    address USV2_FACTORY_ETHEREUM = 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f;
    address SUSHISWAPV2_FACTORY_ETHEREUM =
        0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac;
    address PANCAKESWAPV2_FACTORY_ETHEREUM =
        0x1097053Fd2ea711dad45caCcc45EfF7548fCB362;

    // Uniswap v3
    address DAI_WETH_USV3 = 0xC2e9F25Be6257c210d7Adf0D4Cd6E3E881ba25f8;
    address USDC_WETH_USV3 = 0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640; // 0.05% fee
    address USDC_WETH_USV3_2 = 0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8; // 0.3% fee

    // Uniswap universal router
    address UNIVERSAL_ROUTER = 0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af;

    // Permit2
    address PERMIT2_ADDRESS = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    // Pool Code Init Hashes
    bytes32 USV2_POOL_CODE_INIT_HASH =
        0x96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f;
    bytes32 SUSHIV2_POOL_CODE_INIT_HASH =
        0xe18a34eb0e04b04f7a0ac29a6e80748dca96319b42c54d679cb821dca90c6303;
    bytes32 PANCAKEV2_POOL_CODE_INIT_HASH =
        0x57224589c67f3f30a6b0d7a1b54cf3153ab84563bc609ef41dfb34f8b2974d2d;

    /**
     * @dev Deploys a dummy contract with non-empty bytecode
     */
    function deployDummyContract() internal {
        bytes memory minimalBytecode = hex"01"; // Single-byte bytecode
        // Deploy minimal bytecode
        vm.etch(DUMMY, minimalBytecode);
        vm.etch(DUMMY2, minimalBytecode);
        vm.etch(DUMMY3, minimalBytecode);
    }
}
