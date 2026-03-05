// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../TychoRouterTestSetup.sol";
import "@permit2/src/interfaces/IAllowanceTransfer.sol";
import "@src/executors/UniswapV3Executor.sol";
import {Constants} from "../Constants.sol";
import {Permit2TestHelper} from "../Permit2TestHelper.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";

contract UniswapV3ExecutorExposed is UniswapV3Executor {
    constructor(address _factory, bytes32 _initCode)
        UniswapV3Executor(_factory, _initCode)
    {}

    function decodeData(bytes calldata data)
        external
        pure
        returns (
            address inToken,
            address outToken,
            uint24 fee,
            address target,
            bool zeroForOne
        )
    {
        return _decodeData(data);
    }

    function verifyPairAddress(
        address tokenA,
        address tokenB,
        uint24 fee,
        address target
    ) external view {
        _verifyPairAddress(tokenA, tokenB, fee, target);
    }

    function uniswapV3SwapCallback(
        int256,
        /* amount0Delta */
        int256,
        /* amount1Delta */
        bytes calldata /* data */
    )
        external
    {
        // Use delegatecall to preserve msg.sender
        bytes memory callData =
            abi.encodeWithSignature("getCallbackTransferData(bytes)", msg.data);
        (bool success, bytes memory result) =
            address(this).delegatecall(callData);
        require(success, "Delegatecall failed");

        (, address receiver, address tokenIn, uint256 amount) =
            abi.decode(result, (uint8, address, address, uint256));

        IERC20(tokenIn).transfer(receiver, amount);
        handleCallback(msg.data);
    }
}

contract UniswapV3ExecutorTest is Test, TestUtils, Constants {
    using SafeERC20 for IERC20;

    UniswapV3ExecutorExposed uniswapV3Exposed;
    UniswapV3ExecutorExposed pancakeV3Exposed;
    IERC20 DAI = IERC20(DAI_ADDR);

    function setUp() public {
        uint256 forkBlock = 17323404;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);

        uniswapV3Exposed = new UniswapV3ExecutorExposed(
            USV3_FACTORY_ETHEREUM, USV3_POOL_CODE_INIT_HASH
        );
        pancakeV3Exposed = new UniswapV3ExecutorExposed(
            PANCAKESWAPV3_DEPLOYER_ETHEREUM, PANCAKEV3_POOL_CODE_INIT_HASH
        );
    }

    function testDecodeParams() public view {
        uint24 expectedPoolFee = 500;
        bytes memory data = abi.encodePacked(
            WETH_ADDR, DAI_ADDR, expectedPoolFee, address(3), false
        );

        (
            address tokenIn,
            address tokenOut,
            uint24 fee,
            address target,
            bool zeroForOne
        ) = uniswapV3Exposed.decodeData(data);

        assertEq(tokenIn, WETH_ADDR);
        assertEq(tokenOut, DAI_ADDR);
        assertEq(fee, expectedPoolFee);
        assertEq(target, address(3));
        assertEq(zeroForOne, false);
    }

    function testGetTransferData() public {
        bytes memory params = "";
        (, address receiver, address tokenIn) =
            uniswapV3Exposed.getTransferData(params);

        assertEq(receiver, address(0));
        assertEq(tokenIn, address(0));
    }

    function testGetCallbackTransferData() public {
        uint24 poolFee = 3000;
        uint256 amountOwed = 1000000000000000000;
        bytes memory protocolData = abi.encodePacked(
            WETH_ADDR, DAI_ADDR, poolFee, address(uniswapV3Exposed)
        );
        uint256 dataOffset = 3; // some offset
        uint256 dataLength = protocolData.length;

        bytes memory callbackData = abi.encodePacked(
            bytes4(0xfa461e33),
            int256(amountOwed), // amount0Delta
            int256(0), // amount1Delta
            dataOffset,
            dataLength,
            protocolData
        );
        (, address receiver, address tokenIn, uint256 amount) =
            uniswapV3Exposed.getCallbackTransferData(callbackData);

        assertEq(receiver, address(this));
        assertEq(tokenIn, WETH_ADDR);
        assertEq(amount, amountOwed);
    }

    function testSwapIntegration() public {
        uint256 amountIn = 10 ** 18;
        deal(WETH_ADDR, address(uniswapV3Exposed), amountIn);

        uint256 expAmountOut = 1205_128428842122129186; //Swap 1 WETH for 1205.12 DAI
        bool zeroForOne = false;

        bytes memory data =
            encodeUniswapV3Swap(WETH_ADDR, DAI_ADDR, DAI_WETH_USV3, zeroForOne);

        (uint256 amountOut, address tokenOut) =
            uniswapV3Exposed.swap(amountIn, data, address(this));

        assertGe(amountOut, expAmountOut);
        assertEq(IERC20(WETH_ADDR).balanceOf(address(uniswapV3Exposed)), 0);
        assertGe(IERC20(DAI_ADDR).balanceOf(address(this)), expAmountOut);
        assertEq(tokenOut, DAI_ADDR);
    }

    function testDecodeParamsInvalidDataLength() public {
        bytes memory invalidParams = abi.encodePacked(
            WETH_ADDR,
            DAI_ADDR,
            uint24(500),
            RestrictTransferFrom.TransferType.Transfer,
            address(3),
            false
        );

        vm.expectRevert(UniswapV3Executor__InvalidDataLength.selector);
        uniswapV3Exposed.decodeData(invalidParams);
    }

    function testVerifyPairAddress() public view {
        uniswapV3Exposed.verifyPairAddress(
            WETH_ADDR, DAI_ADDR, 3000, DAI_WETH_USV3
        );
    }

    function testVerifyPairAddressPancake() public view {
        pancakeV3Exposed.verifyPairAddress(
            WETH_ADDR, USDT_ADDR, 500, PANCAKESWAPV3_WETH_USDT_POOL
        );
    }

    function testUSV3Callback() public {
        uint24 poolFee = 3000;
        uint256 amountOwed = 1000000000000000000;
        deal(WETH_ADDR, address(uniswapV3Exposed), amountOwed);
        uint256 initialPoolReserve = IERC20(WETH_ADDR).balanceOf(DAI_WETH_USV3);

        bytes memory protocolData =
            abi.encodePacked(WETH_ADDR, DAI_ADDR, poolFee);
        uint256 dataOffset = 3; // some offset
        uint256 dataLength = protocolData.length;

        bytes memory callbackData = abi.encodePacked(
            bytes4(0xfa461e33),
            int256(amountOwed), // amount0Delta
            int256(0), // amount1Delta
            dataOffset,
            dataLength,
            protocolData
        );

        // transfer funds into the pool - this is taken cared of by the Dispatcher now
        vm.prank(address(uniswapV3Exposed));
        IERC20(WETH_ADDR).transfer(DAI_WETH_USV3, amountOwed);
        vm.startPrank(DAI_WETH_USV3);
        uniswapV3Exposed.handleCallback(callbackData);
        vm.stopPrank();

        uint256 finalPoolReserve = IERC20(WETH_ADDR).balanceOf(DAI_WETH_USV3);
        assertEq(finalPoolReserve - initialPoolReserve, amountOwed);
    }

    function testSwapFailureInvalidTarget() public {
        uint256 amountIn = 10 ** 18;
        deal(WETH_ADDR, address(uniswapV3Exposed), amountIn);
        bool zeroForOne = false;
        address fakePool = DUMMY; // Contract with minimal code

        bytes memory protocolData = abi.encodePacked(
            WETH_ADDR, DAI_ADDR, uint24(3000), fakePool, zeroForOne
        );

        vm.expectRevert(UniswapV3Executor__InvalidTarget.selector);
        uniswapV3Exposed.swap(amountIn, protocolData, BOB);
    }

    function encodeUniswapV3Swap(
        address tokenIn,
        address tokenOut,
        address target,
        bool zero2one
    ) internal view returns (bytes memory) {
        IUniswapV3Pool pool = IUniswapV3Pool(target);
        return abi.encodePacked(tokenIn, tokenOut, pool.fee(), target, zero2one);
    }
}

contract TychoRouterForUniswapV3Test is TychoRouterTestSetup {
    function testSingleSwapUSV3Permit2() public {
        // Trade 1 WETH for DAI with 1 swap on Uniswap V3 using Permit2
        // Tests entire USV3 flow including callback
        // 1 WETH   ->   DAI
        //       (USV3)
        vm.startPrank(ALICE);
        uint256 amountIn = 10 ** 18;
        deal(WETH_ADDR, ALICE, amountIn);
        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(WETH_ADDR, tychoRouterAddr, amountIn);

        uint256 expAmountOut = 1205_128428842122129186; //Swap 1 WETH for 1205.12 DAI
        bool zeroForOne = false;
        bytes memory protocolData =
            encodeUniswapV3Swap(WETH_ADDR, DAI_ADDR, DAI_WETH_USV3, zeroForOne);
        bytes memory swap =
            encodeSingleSwap(address(usv3Executor), protocolData);

        tychoRouter.singleSwapPermit2(
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            expAmountOut - 1,
            ALICE,
            noClientFee(),
            permitSingle,
            signature,
            swap
        );

        uint256 finalBalance = IERC20(DAI_ADDR).balanceOf(ALICE);
        assertGe(finalBalance, expAmountOut);

        vm.stopPrank();
    }

    // Base Network Test
    // Make sure to set the RPC_URL to base network
    function testSwapPancakeswapBaseNetwork() public {
        vm.skip(true);
        vm.rollFork(38001287);

        // Deploy the executor specifically on this Base fork
        UniswapV3ExecutorExposed basePancakeV3Exposed = new UniswapV3ExecutorExposed(
            PANCAKESWAPV3_DEPLOYER, PANCAKEV3_POOL_CODE_INIT_HASH
        );

        uint256 amountIn = 1000 * 10 ** 6;
        bool zeroForOne = true;
        bytes memory protocolData = encodeUniswapV3Swap(
            BASE_USDC, BASE_cbBTC, PANCAKESWAPV3_cbBTC_USDC_POOL, zeroForOne
        );

        deal(BASE_USDC, address(basePancakeV3Exposed), amountIn);

        basePancakeV3Exposed.swap(amountIn, protocolData, BOB);

        // 1000 USDC ~= 0.0095 BTC -> 1 BTC ~= 105k USDC ✅
        assertEq(IERC20(BASE_cbBTC).balanceOf(BOB), 950567);
    }
}
