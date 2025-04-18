// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/UniswapV2Executor.sol";
import "@src/executors/TokenTransfer.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";
import {Constants} from "../Constants.sol";
import {Permit2TestHelper} from "../Permit2TestHelper.sol";

contract UniswapV2ExecutorExposed is UniswapV2Executor {
    constructor(address _factory, bytes32 _initCode, address _permit2, uint256 _feeBps)
        UniswapV2Executor(_factory, _initCode, _permit2, _feeBps)
    {}

    function decodeParams(bytes calldata data)
        external
        pure
        returns (
            IERC20 inToken,
            address target,
            address receiver,
            bool zeroForOne,
            TransferType transferType
        )
    {
        return _decodeData(data);
    }

    function getAmountOut(address target, uint256 amountIn, bool zeroForOne)
        external
        view
        returns (uint256 amount)
    {
        return _getAmountOut(target, amountIn, zeroForOne);
    }

    function verifyPairAddress(address target) external view {
        _verifyPairAddress(target);
    }
}

contract FakeUniswapV2Pool {
    address public token0;
    address public token1;

    constructor(address _tokenA, address _tokenB) {
        token0 = _tokenA < _tokenB ? _tokenA : _tokenB;
        token1 = _tokenA < _tokenB ? _tokenB : _tokenA;
    }
}

contract UniswapV2ExecutorTest is Test, Constants, Permit2TestHelper {
    using SafeERC20 for IERC20;

    UniswapV2ExecutorExposed uniswapV2Exposed;
    UniswapV2ExecutorExposed sushiswapV2Exposed;
    UniswapV2ExecutorExposed pancakeswapV2Exposed;
    IERC20 WETH = IERC20(WETH_ADDR);
    IERC20 DAI = IERC20(DAI_ADDR);
    IAllowanceTransfer permit2;

    function setUp() public {
        uint256 forkBlock = 17323404;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        uniswapV2Exposed = new UniswapV2ExecutorExposed(
            USV2_FACTORY_ETHEREUM, USV2_POOL_CODE_INIT_HASH, PERMIT2_ADDRESS, 30
        );
        sushiswapV2Exposed = new UniswapV2ExecutorExposed(
            SUSHISWAPV2_FACTORY_ETHEREUM,
            SUSHIV2_POOL_CODE_INIT_HASH,
            PERMIT2_ADDRESS,
        30
        );
        pancakeswapV2Exposed = new UniswapV2ExecutorExposed(
            PANCAKESWAPV2_FACTORY_ETHEREUM,
            PANCAKEV2_POOL_CODE_INIT_HASH,
            PERMIT2_ADDRESS,
     25
        );
        permit2 = IAllowanceTransfer(PERMIT2_ADDRESS);
    }

    function testDecodeParams() public view {
        bytes memory params = abi.encodePacked(
            WETH_ADDR,
            address(2),
            address(3),
            false,
            TokenTransfer.TransferType.TRANSFER_TO_PROTOCOL
        );

        (
            IERC20 tokenIn,
            address target,
            address receiver,
            bool zeroForOne,
            TokenTransfer.TransferType transferType
        ) = uniswapV2Exposed.decodeParams(params);

        assertEq(address(tokenIn), WETH_ADDR);
        assertEq(target, address(2));
        assertEq(receiver, address(3));
        assertEq(zeroForOne, false);
        assertEq(
            uint8(TokenTransfer.TransferType.TRANSFER_TO_PROTOCOL),
            uint8(transferType)
        );
    }

    function testDecodeParamsInvalidDataLength() public {
        bytes memory invalidParams =
            abi.encodePacked(WETH_ADDR, address(2), address(3));

        vm.expectRevert(UniswapV2Executor__InvalidDataLength.selector);
        uniswapV2Exposed.decodeParams(invalidParams);
    }

    function testVerifyPairAddress() public view {
        uniswapV2Exposed.verifyPairAddress(WETH_DAI_POOL);
    }

    function testVerifyPairAddressSushi() public view {
        sushiswapV2Exposed.verifyPairAddress(SUSHISWAP_WBTC_WETH_POOL);
    }

    function testVerifyPairAddressPancake() public view {
        pancakeswapV2Exposed.verifyPairAddress(PANCAKESWAP_WBTC_WETH_POOL);
    }

    function testInvalidTarget() public {
        address fakePool = address(new FakeUniswapV2Pool(WETH_ADDR, DAI_ADDR));
        vm.expectRevert(UniswapV2Executor__InvalidTarget.selector);
        uniswapV2Exposed.verifyPairAddress(fakePool);
    }

    function testAmountOut() public view {
        uint256 amountOut =
            uniswapV2Exposed.getAmountOut(WETH_DAI_POOL, 10 ** 18, false);
        uint256 expAmountOut = 1847751195973566072891;
        assertEq(amountOut, expAmountOut);
    }

    // triggers a uint112 overflow on purpose
    function testAmountOutInt112Overflow() public view {
        address target = 0x0B9f5cEf1EE41f8CCCaA8c3b4c922Ab406c980CC;
        uint256 amountIn = 83638098812630667483959471576;

        uint256 amountOut =
            uniswapV2Exposed.getAmountOut(target, amountIn, true);

        assertGe(amountOut, 0);
    }

    function testSwapWithTransfer() public {
        uint256 amountIn = 10 ** 18;
        uint256 amountOut = 1847751195973566072891;
        bool zeroForOne = false;
        bytes memory protocolData = abi.encodePacked(
            WETH_ADDR,
            WETH_DAI_POOL,
            BOB,
            zeroForOne,
            uint8(TokenTransfer.TransferType.TRANSFER_TO_PROTOCOL)
        );

        deal(WETH_ADDR, address(uniswapV2Exposed), amountIn);
        uniswapV2Exposed.swap(amountIn, protocolData);

        uint256 finalBalance = DAI.balanceOf(BOB);
        assertGe(finalBalance, amountOut);
    }

    function testSwapWithTransferFrom() public {
        uint256 amountIn = 10 ** 18;
        uint256 amountOut = 1847751195973566072891;
        bool zeroForOne = false;
        bytes memory protocolData = abi.encodePacked(
            WETH_ADDR,
            WETH_DAI_POOL,
            BOB,
            zeroForOne,
            uint8(TokenTransfer.TransferType.TRANSFER_FROM_TO_PROTOCOL)
        );

        deal(WETH_ADDR, address(this), amountIn);
        IERC20(WETH_ADDR).approve(address(uniswapV2Exposed), amountIn);

        uniswapV2Exposed.swap(amountIn, protocolData);

        uint256 finalBalance = DAI.balanceOf(BOB);
        assertGe(finalBalance, amountOut);
    }

    function testSwapWithPermit2TransferFrom() public {
        uint256 amountIn = 10 ** 18;
        uint256 amountOut = 1847751195973566072891;
        bool zeroForOne = false;
        bytes memory protocolData = abi.encodePacked(
            WETH_ADDR,
            WETH_DAI_POOL,
            ALICE,
            zeroForOne,
            uint8(TokenTransfer.TransferType.TRANSFER_PERMIT2_TO_PROTOCOL)
        );

        deal(WETH_ADDR, ALICE, amountIn);
        vm.startPrank(ALICE);
        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(
            WETH_ADDR, address(uniswapV2Exposed), amountIn
        );

        // Assume the permit2.approve method will be called from the TychoRouter
        // Replicate this scenario in this test.
        permit2.permit(ALICE, permitSingle, signature);

        uniswapV2Exposed.swap(amountIn, protocolData);
        vm.stopPrank();

        uint256 finalBalance = DAI.balanceOf(ALICE);
        assertGe(finalBalance, amountOut);
    }

    function testSwapNoTransfer() public {
        uint256 amountIn = 10 ** 18;
        uint256 amountOut = 1847751195973566072891;
        bool zeroForOne = false;
        bytes memory protocolData = abi.encodePacked(
            WETH_ADDR,
            WETH_DAI_POOL,
            BOB,
            zeroForOne,
            uint8(TokenTransfer.TransferType.NONE)
        );

        deal(WETH_ADDR, address(this), amountIn);
        IERC20(WETH_ADDR).transfer(address(WETH_DAI_POOL), amountIn);
        uniswapV2Exposed.swap(amountIn, protocolData);

        uint256 finalBalance = DAI.balanceOf(BOB);
        assertGe(finalBalance, amountOut);
    }

    function testDecodeIntegration() public view {
        // Generated by the ExecutorStrategyEncoder - test_executor_strategy_encode
        bytes memory protocolData =
            hex"c02aaa39b223fe8d0a0e5c4f27ead9083c756cc288e6a0c2ddd26feeb64f039a2c41296fcb3f564000000000000000000000000000000000000000010000";

        (
            IERC20 tokenIn,
            address target,
            address receiver,
            bool zeroForOne,
            TokenTransfer.TransferType transferType
        ) = uniswapV2Exposed.decodeParams(protocolData);

        assertEq(address(tokenIn), WETH_ADDR);
        assertEq(target, 0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640);
        assertEq(receiver, 0x0000000000000000000000000000000000000001);
        assertEq(zeroForOne, false);
        // TRANSFER = 0
        assertEq(0, uint8(transferType));
    }

    function testSwapIntegration() public {
        // Generated by the ExecutorStrategyEncoder - test_executor_strategy_encode
        bytes memory protocolData =
            hex"c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a478c2975ab1ea89e8196811f51a7b7ade33eb111d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e0000";
        uint256 amountIn = 10 ** 18;
        uint256 amountOut = 1847751195973566072891;
        deal(WETH_ADDR, address(uniswapV2Exposed), amountIn);
        uniswapV2Exposed.swap(amountIn, protocolData);

        uint256 finalBalance = DAI.balanceOf(BOB);
        assertGe(finalBalance, amountOut);
    }

    function testSwapFailureInvalidTarget() public {
        uint256 amountIn = 10 ** 18;
        bool zeroForOne = false;
        address fakePool = address(new FakeUniswapV2Pool(WETH_ADDR, DAI_ADDR));
        bytes memory protocolData = abi.encodePacked(
            WETH_ADDR,
            fakePool,
            BOB,
            zeroForOne,
            uint8(TokenTransfer.TransferType.TRANSFER_TO_PROTOCOL)
        );

        deal(WETH_ADDR, address(uniswapV2Exposed), amountIn);
        vm.expectRevert(UniswapV2Executor__InvalidTarget.selector);
        uniswapV2Exposed.swap(amountIn, protocolData);
    }

    // Base Network Tests
    // Make sure to set the RPC_URL to base network
    function testSwapBaseNetwork() public {
        vm.skip(true);
        vm.rollFork(26857267);
        uint256 amountIn = 10 * 10 ** 6;
        bool zeroForOne = true;
        bytes memory protocolData = abi.encodePacked(
            BASE_USDC,
            USDC_MAG7_POOL,
            BOB,
            zeroForOne,
            uint8(TokenTransfer.TransferType.TRANSFER_TO_PROTOCOL)
        );

        deal(BASE_USDC, address(uniswapV2Exposed), amountIn);

        uniswapV2Exposed.swap(amountIn, protocolData);

        assertEq(IERC20(BASE_MAG7).balanceOf(BOB), 1379830606);
    }
}
