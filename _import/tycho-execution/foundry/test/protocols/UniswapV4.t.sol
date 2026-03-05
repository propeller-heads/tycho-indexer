// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../../src/executors/UniswapV4Executor.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../TestUtils.sol";
import "../TychoRouterTestSetup.sol";
import "./UniswapV4Utils.sol";
import "@src/executors/UniswapV4Executor.sol";
import {Constants} from "../Constants.sol";
import {SafeCallback} from "@uniswap/v4-periphery/src/base/SafeCallback.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";

contract UniswapV4ExecutorExposed is UniswapV4Executor {
    using SafeERC20 for IERC20;
    constructor(IPoolManager _POOL_MANAGER, address _ANGSTROM_HOOK)
        UniswapV4Executor(_POOL_MANAGER, _ANGSTROM_HOOK)
    {}

    function decodeData(bytes calldata data)
        external
        view
        returns (
            address tokenIn,
            address tokenOut,
            bool zeroForOne,
            UniswapV4Pool[] memory pools
        )
    {
        return _decodeData(data);
    }

    fallback(
        bytes calldata /*data*/
    )
        external
        returns (bytes memory)
    {
        (
            RestrictTransferFrom.TransferType transferType,
            address receiver,
            address tokenIn,
            uint256 amount
        ) = this.getCallbackTransferData(msg.data);
        if (transferType == RestrictTransferFrom.TransferType.Transfer) {
            IERC20(tokenIn).safeTransfer(receiver, amount);
        }
        bytes calldata stripped = msg.data[68:];
        return abi.encode(_unlockCallback(stripped));
    }
}

contract UniswapV4ExecutorTest is Constants, TestUtils {
    using SafeERC20 for IERC20;

    UniswapV4ExecutorExposed uniswapV4Exposed;
    IERC20 USDE = IERC20(USDE_ADDR);
    IERC20 USDT = IERC20(USDT_ADDR);
    IERC20 USDC = IERC20(USDC_ADDR);

    function setUp() public {
        uint256 forkBlock = 22689128;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        uniswapV4Exposed = new UniswapV4ExecutorExposed(
            IPoolManager(POOL_MANAGER), ANGSTROM_HOOK
        );
    }

    function testDecodeParams() public view {
        bool zeroForOne = true;
        uint24 pool1Fee = 500;
        int24 tickSpacing1 = 60;
        uint24 pool2Fee = 1000;
        int24 tickSpacing2 = -10;

        UniswapV4Executor.UniswapV4Pool[] memory pools =
            new UniswapV4Executor.UniswapV4Pool[](2);
        pools[0] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: USDT_ADDR,
            fee: pool1Fee,
            tickSpacing: tickSpacing1,
            hook: address(0),
            hookData: bytes("")
        });
        pools[1] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: USDE_ADDR,
            fee: pool2Fee,
            tickSpacing: tickSpacing2,
            hook: address(0),
            hookData: bytes("0x12345")
        });

        bytes memory data = UniswapV4Utils.encodeExactInput(
            USDE_ADDR, USDT_ADDR, zeroForOne, pools
        );

        (
            address tokenIn,
            address tokenOut,
            bool zeroForOneDecoded,
            UniswapV4Executor.UniswapV4Pool[] memory decodedPools
        ) = uniswapV4Exposed.decodeData(data);

        assertEq(tokenIn, USDE_ADDR);
        assertEq(tokenOut, USDT_ADDR);
        assertEq(zeroForOneDecoded, zeroForOne);
        assertEq(decodedPools[0].hook, address(0));
        assertEq(decodedPools.length, 2);
        assertEq(decodedPools[0].intermediaryToken, USDT_ADDR);
        assertEq(decodedPools[0].fee, pool1Fee);
        assertEq(decodedPools[0].tickSpacing, tickSpacing1);
        assertEq(decodedPools[1].intermediaryToken, USDE_ADDR);
        assertEq(decodedPools[1].fee, pool2Fee);
        assertEq(decodedPools[1].tickSpacing, tickSpacing2);
        assertEq(decodedPools[1].hookData, bytes("0x12345"));
    }

    function testSingleSwap() public {
        uint256 amountIn = 100 ether;
        deal(USDE_ADDR, address(uniswapV4Exposed), amountIn);
        uint256 usdeBalanceBeforePool = USDE.balanceOf(POOL_MANAGER);
        uint256 usdeBalanceBeforeSwapExecutor =
            USDE.balanceOf(address(uniswapV4Exposed));

        UniswapV4Executor.UniswapV4Pool[] memory pools =
            new UniswapV4Executor.UniswapV4Pool[](1);
        pools[0] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: USDT_ADDR,
            fee: uint24(100),
            tickSpacing: int24(1),
            hook: address(0),
            hookData: bytes("")
        });

        bytes memory data =
            UniswapV4Utils.encodeExactInput(USDE_ADDR, USDT_ADDR, true, pools);

        (uint256 amountOut, address tokenOut) =
            uniswapV4Exposed.swap(amountIn, data, ALICE);
        assertEq(USDE.balanceOf(POOL_MANAGER), usdeBalanceBeforePool + amountIn);
        assertEq(
            USDE.balanceOf(address(uniswapV4Exposed)),
            usdeBalanceBeforeSwapExecutor - amountIn
        );
        assertTrue(USDT.balanceOf(ALICE) == amountOut);
        assertEq(tokenOut, USDT_ADDR);
    }

    function testSingleSwapIntegration() public {
        // USDE -> USDT
        bytes memory protocolData =
            loadCallDataFromFile("test_encode_uniswap_v4_simple_swap");
        uint256 amountIn = 100 ether;
        deal(USDE_ADDR, address(uniswapV4Exposed), amountIn);
        uint256 usdeBalanceBeforePool = USDE.balanceOf(POOL_MANAGER);
        uint256 usdeBalanceBeforeSwapExecutor =
            USDE.balanceOf(address(uniswapV4Exposed));

        (uint256 amountOut, address tokenOut) =
            uniswapV4Exposed.swap(amountIn, protocolData, ALICE);
        assertEq(USDE.balanceOf(POOL_MANAGER), usdeBalanceBeforePool + amountIn);
        assertEq(
            USDE.balanceOf(ALICE), usdeBalanceBeforeSwapExecutor - amountIn
        );
        assertTrue(USDT.balanceOf(ALICE) == amountOut);
        assertEq(tokenOut, USDT_ADDR);
    }

    function testMultipleSwap() public {
        // USDE -> USDT -> WBTC
        uint256 amountIn = 100 ether;
        deal(USDE_ADDR, address(uniswapV4Exposed), amountIn);
        uint256 usdeBalanceBeforePool = USDE.balanceOf(POOL_MANAGER);
        uint256 usdeBalanceBeforeSwapExecutor =
            USDE.balanceOf(address(uniswapV4Exposed));

        UniswapV4Executor.UniswapV4Pool[] memory pools =
            new UniswapV4Executor.UniswapV4Pool[](2);
        pools[0] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: USDT_ADDR,
            fee: uint24(100),
            tickSpacing: int24(1),
            hook: address(0),
            hookData: bytes("")
        });
        pools[1] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: WBTC_ADDR,
            fee: uint24(3000),
            tickSpacing: int24(60),
            hook: address(0),
            hookData: bytes("")
        });

        bytes memory data =
            UniswapV4Utils.encodeExactInput(USDE_ADDR, WBTC_ADDR, true, pools);

        (uint256 amountOut, address tokenOut) =
            uniswapV4Exposed.swap(amountIn, data, ALICE);
        assertEq(USDE.balanceOf(POOL_MANAGER), usdeBalanceBeforePool + amountIn);
        assertEq(
            USDE.balanceOf(address(uniswapV4Exposed)),
            usdeBalanceBeforeSwapExecutor - amountIn
        );
        assertTrue(IERC20(WBTC_ADDR).balanceOf(ALICE) == amountOut);
        assertEq(tokenOut, WBTC_ADDR);
    }

    function testMultipleSwapIntegration() public {
        // USDE -> USDT -> WBTC
        bytes memory protocolData =
            loadCallDataFromFile("test_encode_uniswap_v4_sequential_swap");

        uint256 amountIn = 100 ether;
        deal(USDE_ADDR, address(uniswapV4Exposed), amountIn);
        uint256 usdeBalanceBeforePool = USDE.balanceOf(POOL_MANAGER);
        uint256 usdeBalanceBeforeSwapExecutor =
            USDE.balanceOf(address(uniswapV4Exposed));

        (uint256 amountOut, address tokenOut) =
            uniswapV4Exposed.swap(amountIn, protocolData, ALICE);
        assertEq(USDE.balanceOf(POOL_MANAGER), usdeBalanceBeforePool + amountIn);
        assertEq(
            USDE.balanceOf(address(uniswapV4Exposed)),
            usdeBalanceBeforeSwapExecutor - amountIn
        );
        assertTrue(IERC20(WBTC_ADDR).balanceOf(ALICE) == amountOut);
        assertEq(tokenOut, WBTC_ADDR);
    }

    function testSingleSwapEulerHook() public {
        // Replicating tx: 0xb372306a81c6e840f4ec55f006da6b0b097f435802a2e6fd216998dd12fb4aca
        address hook = address(0x69058613588536167BA0AA94F0CC1Fe420eF28a8);

        uint256 amountIn = 7407000000;
        deal(USDC_ADDR, address(uniswapV4Exposed), amountIn);
        uint256 usdcBalanceBeforeSwapExecutor =
            USDC.balanceOf(address(uniswapV4Exposed));

        UniswapV4Executor.UniswapV4Pool[] memory pools =
            new UniswapV4Executor.UniswapV4Pool[](1);
        pools[0] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: WETH_ADDR,
            fee: uint24(500),
            tickSpacing: int24(1),
            hook: hook,
            hookData: bytes("")
        });

        bytes memory data =
            UniswapV4Utils.encodeExactInput(USDC_ADDR, WETH_ADDR, true, pools);

        (uint256 amountOut, address tokenOut) =
            uniswapV4Exposed.swap(amountIn, data, ALICE);
        assertEq(amountOut, 2681115183499232721);
        assertEq(
            USDC.balanceOf(address(uniswapV4Exposed)),
            usdcBalanceBeforeSwapExecutor - amountIn
        );
        assertTrue(IERC20(WETH_ADDR).balanceOf(ALICE) == amountOut);
        assertEq(tokenOut, WETH_ADDR);
    }
}

contract UniswapV4ExecutorTestForEuler is Constants, TestUtils {
    /* These tests are necessary because Euler works a little differently from general UniswapV4 logic.
    In the previous version of the UniswapV4Executor we are only sending the user's tokens into the Pool Manager
    after we call swap on it. This is ok because the Pool Manager tracks the debts and accepts everything as long
    as the tokens are transfers inside of the unlock callback. However, Euler expects the funds to already be
    in the Pool Manager when beforeSwap is called. This is not a problem for tokens that the Pool Manager has a
    lot of, but for tokens with low balances this makes the tx fail. We need to transfer the tokens into
    the Pool Manager before we call swap on it.
    The only risk here is that we are assuming that the amount_in will never change. In the previous version, we
    were confirming this amount with the currencyDelta of the Pool Manager. Now we pray.
    */
    using SafeERC20 for IERC20;

    UniswapV4ExecutorExposed uniswapV4Exposed;
    IERC20 USDT = IERC20(USDT_ADDR);
    IERC20 USDC = IERC20(USDC_ADDR);
    IERC20 RLUSD = IERC20(RLUSD_ADDR);
    IERC20 WBTC = IERC20(WBTC_ADDR);

    function setUp() public {
        uint256 forkBlock = 23535338;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        uniswapV4Exposed = new UniswapV4ExecutorExposed(
            IPoolManager(POOL_MANAGER), ANGSTROM_HOOK
        );
    }

    function testSingleSwapEulerLowBalance() public {
        uint256 amountIn = 134187695711754971245517404;
        deal(RLUSD_ADDR, address(uniswapV4Exposed), amountIn);
        address eulerProxy = 0xe1Ce9AF672f8854845E5474400B6ddC7AE458a10;
        uint256 rlusdEulerBalanceBefore = RLUSD.balanceOf(eulerProxy);

        UniswapV4Executor.UniswapV4Pool[] memory pools =
            new UniswapV4Executor.UniswapV4Pool[](1);
        pools[0] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: USDT_ADDR,
            fee: uint24(50),
            tickSpacing: int24(1),
            hook: address(0xF87ACF8428F2f9403AAA0256A7272d6549ECa8A8),
            hookData: bytes("")
        });

        bytes memory data =
            UniswapV4Utils.encodeExactInput(RLUSD_ADDR, USDT_ADDR, true, pools);

        (uint256 amountOut, address tokenOut) =
            uniswapV4Exposed.swap(amountIn, data, ALICE);
        assertEq(
            RLUSD.balanceOf(eulerProxy), rlusdEulerBalanceBefore + amountIn
        );
        assertTrue(USDT.balanceOf(ALICE) == amountOut);
        assertEq(tokenOut, USDT_ADDR);
    }

    function testMultipleSwapEulerLowBalance() public {
        // RLUSD -(euler)-> USDT -> WBTC
        uint256 amountIn = 134187695711754971245517404;
        deal(RLUSD_ADDR, address(uniswapV4Exposed), amountIn);
        address eulerProxy = 0xe1Ce9AF672f8854845E5474400B6ddC7AE458a10;
        uint256 rlusdEulerBalanceBefore = RLUSD.balanceOf(eulerProxy);

        UniswapV4Executor.UniswapV4Pool[] memory pools =
            new UniswapV4Executor.UniswapV4Pool[](2);
        pools[0] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: USDT_ADDR,
            fee: uint24(50),
            tickSpacing: int24(1),
            hook: address(0xF87ACF8428F2f9403AAA0256A7272d6549ECa8A8),
            hookData: bytes("")
        });
        pools[1] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: WBTC_ADDR,
            fee: uint24(3000),
            tickSpacing: int24(60),
            hook: address(0),
            hookData: bytes("")
        });

        bytes memory data =
            UniswapV4Utils.encodeExactInput(RLUSD_ADDR, WBTC_ADDR, true, pools);

        (uint256 amountOut, address tokenOut) =
            uniswapV4Exposed.swap(amountIn, data, ALICE);
        assertEq(
            RLUSD.balanceOf(eulerProxy), rlusdEulerBalanceBefore + amountIn
        );
        assertTrue(WBTC.balanceOf(ALICE) == amountOut);
        assertEq(tokenOut, WBTC_ADDR);
    }

    function testDoubleEulerSwapLowBalance() public {
        // 10 USDC -(euler)-> RLUSD -(euler)-> USDT
        // We use RLUSD pools because it doesn't have significant balance on the pool
        // manager contract
        uint256 amountIn = 10_000000;
        deal(USDC_ADDR, address(uniswapV4Exposed), amountIn);
        address eulerProxy = 0xe0a80d35bB6618CBA260120b279d357978c42BCE;
        uint256 usdcEulerBalanceBefore = USDC.balanceOf(eulerProxy);

        UniswapV4Executor.UniswapV4Pool[] memory pools =
            new UniswapV4Executor.UniswapV4Pool[](2);

        // USDC -> RLUSD
        pools[0] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: RLUSD_ADDR,
            fee: uint24(40),
            tickSpacing: int24(1),
            hook: address(0x8B0DAD43EA6E83B2A6a0de18c5985030ba0Da8A8),
            hookData: bytes("")
        });
        // RLUSD -> USDT
        pools[1] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: USDT_ADDR,
            fee: uint24(50),
            tickSpacing: int24(1),
            hook: address(0xF87ACF8428F2f9403AAA0256A7272d6549ECa8A8),
            hookData: bytes("")
        });

        bytes memory data =
            UniswapV4Utils.encodeExactInput(USDC_ADDR, USDT_ADDR, true, pools);

        (uint256 amountOut, address tokenOut) =
            uniswapV4Exposed.swap(amountIn, data, ALICE);
        assertEq(USDC.balanceOf(eulerProxy), usdcEulerBalanceBefore + amountIn);
        assertTrue(USDT.balanceOf(ALICE) == amountOut);
        assertEq(tokenOut, USDT_ADDR);
    }

    function testMultipleSwapLastSwapEuler() public {
        // USDC -> RLUSD -(euler)- > USDT
        // Sanity check to see if a grouped swap with Euler in the last hop works
        uint256 amountIn = 134187695711754971245517404;
        deal(USDC_ADDR, address(uniswapV4Exposed), amountIn);

        UniswapV4Executor.UniswapV4Pool[] memory pools =
            new UniswapV4Executor.UniswapV4Pool[](2);
        pools[0] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: RLUSD_ADDR,
            fee: uint24(500),
            tickSpacing: int24(10),
            hook: address(0),
            hookData: bytes("")
        });
        pools[1] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: USDT_ADDR,
            fee: uint24(50),
            tickSpacing: int24(1),
            hook: address(0xF87ACF8428F2f9403AAA0256A7272d6549ECa8A8),
            hookData: bytes("")
        });

        bytes memory data =
            UniswapV4Utils.encodeExactInput(USDC_ADDR, USDT_ADDR, false, pools);

        (uint256 amountOut, address tokenOut) =
            uniswapV4Exposed.swap(amountIn, data, ALICE);
        assertTrue(USDT.balanceOf(ALICE) == amountOut);
        assertEq(tokenOut, USDT_ADDR);
    }
}

contract TychoRouterForUniswapV4Test is TychoRouterTestSetup {
    function testSingleSwapUSV4CallbackPermit2() public {
        vm.startPrank(ALICE);
        uint256 amountIn = 100 ether;
        deal(USDE_ADDR, ALICE, amountIn);
        (
            IAllowanceTransfer.PermitSingle memory permitSingle,
            bytes memory signature
        ) = handlePermit2Approval(USDE_ADDR, tychoRouterAddr, amountIn);

        UniswapV4Executor.UniswapV4Pool[] memory pools =
            new UniswapV4Executor.UniswapV4Pool[](1);
        pools[0] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: USDT_ADDR,
            fee: uint24(100),
            tickSpacing: int24(1),
            hook: address(0),
            hookData: bytes("")
        });

        bytes memory protocolData =
            UniswapV4Utils.encodeExactInput(USDE_ADDR, USDT_ADDR, true, pools);

        bytes memory swap =
            encodeSingleSwap(address(usv4Executor), protocolData);

        tychoRouter.singleSwapPermit2(
            amountIn,
            USDE_ADDR,
            USDT_ADDR,
            99943850,
            ALICE,
            noClientFee(),
            permitSingle,
            signature,
            swap
        );

        assertEq(IERC20(USDT_ADDR).balanceOf(ALICE), 99963618);
        vm.stopPrank();
    }

    function testSplitSwapMultipleUSV4Callback() public {
        // This test has two uniswap v4 hops that will be executed inside of the V4 pool manager
        // USDE -> USDT -> WBTC
        uint256 amountIn = 100 ether;
        deal(USDE_ADDR, ALICE, amountIn);

        UniswapV4Executor.UniswapV4Pool[] memory pools =
            new UniswapV4Executor.UniswapV4Pool[](2);
        pools[0] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: USDT_ADDR,
            fee: uint24(100),
            tickSpacing: int24(1),
            hook: address(0),
            hookData: bytes("")
        });
        pools[1] = UniswapV4Executor.UniswapV4Pool({
            intermediaryToken: WBTC_ADDR,
            fee: uint24(3000),
            tickSpacing: int24(60),
            hook: address(0),
            hookData: bytes("")
        });

        bytes memory protocolData =
            UniswapV4Utils.encodeExactInput(USDE_ADDR, WBTC_ADDR, true, pools);

        bytes memory swap =
            encodeSingleSwap(address(usv4Executor), protocolData);

        vm.startPrank(ALICE);
        IERC20(USDE_ADDR).approve(tychoRouterAddr, amountIn);
        tychoRouter.singleSwap(
            amountIn, USDE_ADDR, WBTC_ADDR, 118280, ALICE, noClientFee(), swap
        );

        assertEq(IERC20(WBTC_ADDR).balanceOf(ALICE), 118281);
    }

    function testSingleUSV4IntegrationGroupedSwap() public {
        // Test created with calldata from our router encoder.

        // Performs a single swap from USDC to PEPE though ETH using two
        // consecutive USV4 pools. It's a single swap because it is a consecutive grouped swaps
        //
        //   USDC ──(USV4)──> ETH ───(USV4)──> PEPE
        //
        deal(USDC_ADDR, ALICE, 1 ether);
        uint256 balanceBefore = IERC20(PEPE_ADDR).balanceOf(ALICE);

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);
        bytes memory callData = loadCallDataFromFile(
            "test_single_encoding_strategy_usv4_grouped_swap"
        );
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = IERC20(PEPE_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, 123172000092711286554274694);
    }

    function testSingleUSV4IntegrationInputETH() public {
        // Test created with calldata from our router encoder.

        // Performs a single swap from ETH to PEPE without wrapping or unwrapping
        //
        //   ETH ───(USV4)──> PEPE
        //
        deal(ALICE, 1 ether);
        uint256 balanceBefore = IERC20(PEPE_ADDR).balanceOf(ALICE);

        bytes memory callData =
            loadCallDataFromFile("test_single_encoding_strategy_usv4_eth_in");
        (bool success,) = tychoRouterAddr.call{value: 1 ether}(callData);

        vm.stopPrank();

        uint256 balanceAfter = IERC20(PEPE_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, 235610487387677804636755778);
    }

    function testSingleUSV4IntegrationOutputETH() public {
        // Test created with calldata from our router encoder.

        // Performs a single swap from USDC to ETH without wrapping or unwrapping
        //
        //   USDC ───(USV4)──> ETH
        //
        deal(USDC_ADDR, ALICE, 3000_000000);
        uint256 balanceBefore = ALICE.balance;

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);

        bytes memory callData =
            loadCallDataFromFile("test_single_encoding_strategy_usv4_eth_out");
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = ALICE.balance;

        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, 1474406268748155809);
    }
}

contract TychoRouterForUniswapV4AndEulerTest is TychoRouterTestSetup {
    function getForkBlock() public view virtual override returns (uint256) {
        return 22689128;
    }

    function testSingleUSV4AndHooksIntegrationGroupedSwap() public {
        // Test created with calldata from our router encoder.
        // Tests that uniswap_v4 and uniswap_v4_hooks can be grouped together
        //
        //   WETH ───(USV4 with Euler)──> USDC ──(USV4)──> ETH

        uint256 amountIn = 1 ether;
        deal(WETH_ADDR, ALICE, amountIn);
        uint256 balanceBefore = ALICE.balance;

        // Approve permit2
        vm.startPrank(ALICE);
        IERC20(WETH_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);
        bytes memory callData = loadCallDataFromFile(
            "test_single_encoding_strategy_usv4_and_hooks_grouped_swap"
        );
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = ALICE.balance;

        assertTrue(success, "Call Failed");
        assertGt(balanceAfter - balanceBefore, 0.9 ether); // At least 0.9 ETH
    }
}

contract TychoRouterUSV4FeeTokenTest is TychoRouterTestSetup {
    function getForkBlock() public view virtual override returns (uint256) {
        return 23550000;
    }

    function testSwapTWIFToUSDCViaV4() public {
        // Full TychoRouter swap of TWIF (6% fee-on-transfer) to
        // USDC through a real UniswapV4 pool.
        //
        //   TWIF ───(USV4, fee=10000, tick=200)──> USDC
        //
        // TWIF charges 6% on every transfer, including to the
        // V4 Pool Manager. Before the fix, the executor passed
        // the full amountIn to V4's swap, but only 94% arrived
        // after the fee deduction, causing CurrencyNotSettled().
        address TWIF = 0x2Dd636C514Bb4705c756D161585Ff9ec665f18A2;

        // TWIF is nearly worthless (~7.6e-10 USDC per token).
        // Use a large amount so the swap produces >=1 USDC.
        uint256 amountIn = 1e34;

        deal(TWIF, ALICE, amountIn);

        vm.startPrank(ALICE);
        IERC20(TWIF).approve(PERMIT2_ADDRESS, type(uint256).max);

        bytes memory callData = loadCallDataFromFile(
            "test_single_encoding_strategy_usv4_twif_fee_token"
        );
        (bool success,) = tychoRouterAddr.call(callData);
        vm.stopPrank();

        uint256 usdcReceived = IERC20(USDC_ADDR).balanceOf(ALICE);

        assertTrue(success, "TychoRouter swap failed");
        assertGt(usdcReceived, 0, "Should receive USDC");
    }

    function testSwapUSDCToTWIFViaV4() public {
        // Full TychoRouter swap of USDC to TWIF (6% fee-on-transfer)
        // through a real UniswapV4 pool.
        //
        //   USDC ───(USV4, fee=10000, tick=200)──> TWIF
        //
        // TWIF charges 6% on the output transfer from the V4 Pool
        // Manager to the receiver. Before the fix, the executor
        // reported the pre-fee amount from the V4 delta, causing
        // TychoRouter__AmountOutNotFullyReceived(...)
        address TWIF = 0x2Dd636C514Bb4705c756D161585Ff9ec665f18A2;
        uint256 amountIn = 100_000000; // 100 USDC

        deal(USDC_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(PERMIT2_ADDRESS, type(uint256).max);

        bytes memory callData = loadCallDataFromFile(
            "test_single_encoding_strategy_usv4_twif_fee_token_output"
        );
        (bool success,) = tychoRouterAddr.call(callData);
        vm.stopPrank();

        uint256 twifReceived = IERC20(TWIF).balanceOf(ALICE);

        assertTrue(success, "TychoRouter swap failed");
        assertGt(twifReceived, 0, "Should receive TWIF");
    }

    // TODO delete this test. This was just for you to see my reasoning.
    function testFeeTokenBehaviorOnV4() public {
        // All fee-on-transfer tokens found in V4 pools
        address[14] memory tokens = [
            0x14feE680690900BA0ccCfC76AD70Fd1b95D10e16, // $PAAL
            0xD1F2586790a5bD6DA1e443441df53aF6EC213D83, // LEDGER
            0xD1e64bcc904Cfdc19d0FABA155a9EdC69b4bcdAe, // PIKA
            0xf9902EdfCa4F49DcaEBC335C73aEbD82C79C2886, // ADO
            0xc11158c5dA9db1D553ED28f0C2BA1CbEDD42CFcb, // wPAW
            0xFbD5fD3f85e9f4c5E8B40EEC9F8B8ab1cAAa146b, // TREAT
            0x2Dd636C514Bb4705c756D161585Ff9ec665f18A2, // TWIF
            0x851F679A5eDfb16E7cF1ad157C6995b7E7F333F2, // TrumpBucks
            0x3ADE1cED4D61D45d735E08880e66f4d8f1E1D9b1, // BP
            0xEA87148a703ADc0DE89dB2aC2b6b381093aE8ee0, // IRIS
            0xfC8e44851ccbD13D8F865d65b2425B33dC1E2570, // XOE
            0x8162b5Bc8F651007cC38a09F557BaB2Bf4CEFb5b, // STRM
            0x01eefFCD9a10266ed00946121DF097eeD173b43D, // XD
            0xcDbddbdEFB0eE3eF03a89AFcd714aa4ef310D567 // VERTAI
        ];

        string[14] memory names = [
            "$PAAL",
            "LEDGER",
            "PIKA",
            "ADO",
            "wPAW",
            "TREAT",
            "TWIF",
            "TrumpBucks",
            "BP",
            "IRIS",
            "XOE",
            "STRM",
            "XD",
            "VERTAI"
        ];

        uint256 amount = 1e18;
        uint256 feeTokenCount = 0;

        for (uint256 i = 0; i < tokens.length; i++) {
            uint256 codeSize;
            address token = tokens[i];
            assembly {
                codeSize := extcodesize(token)
            }
            if (codeSize == 0) {
                console.log(names[i], " -- not deployed --");
                continue;
            }

            deal(token, ALICE, amount);
            uint256 pmBefore = IERC20(token).balanceOf(POOL_MANAGER);
            try this.doTransfer(token, ALICE, POOL_MANAGER, amount) returns (
                uint256
            ) {
                uint256 pmAfter = IERC20(token).balanceOf(POOL_MANAGER);
                uint256 fee = amount - (pmAfter - pmBefore);
                if (fee > 0) {
                    feeTokenCount++;
                }
                console.log(names[i], " fee:", fee);
            } catch {
                console.log(names[i], " -- transfer reverted --");
            }
        }

        console.log("");
        console.log("Tokens that charged a fee:", feeTokenCount);
        console.log("Total tokens tested:", tokens.length);
    }

    /// @dev External helper so we can try/catch transfers
    function doTransfer(address token, address from, address to, uint256 amount)
        external
        returns (uint256 received)
    {
        uint256 before = IERC20(token).balanceOf(to);
        vm.prank(from);
        IERC20(token).transfer(to, amount);
        received = IERC20(token).balanceOf(to) - before;
    }
}
