pragma solidity ^0.8.26;

import "../TychoRouterTestSetup.sol";
import "@permit2/src/interfaces/IAllowanceTransfer.sol";
import "@src/executors/UniswapV3Executor.sol";
import {Constants} from "../Constants.sol";
import {Permit2TestHelper} from "../Permit2TestHelper.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";

contract UniswapV3ExecutorExposed is UniswapV3Executor {
    constructor() UniswapV3Executor() {}

    function decodeData(bytes calldata data)
        external
        pure
        returns (address target, bool zeroForOne)
    {
        return _decodeData(data);
    }

    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata /* data */
    ) external {
        // Use delegatecall to preserve msg.sender
        bytes memory callData =
            abi.encodeWithSignature("getCallbackTransferData(bytes)", msg.data);
        (bool success, bytes memory result) =
            address(this).delegatecall(callData);
        require(success, "Delegatecall failed");

        (, address receiver, address tokenIn) =
            abi.decode(result, (uint8, address, address));

        uint256 amount =
            amount0Delta > 0 ? uint256(amount0Delta) : uint256(amount1Delta);
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

        uniswapV3Exposed = new UniswapV3ExecutorExposed();
        pancakeV3Exposed = new UniswapV3ExecutorExposed();
    }

    function testDecodeParams() public view {
        uint24 expectedPoolFee = 500;
        bytes memory data = abi.encodePacked(
            WETH_ADDR, DAI_ADDR, expectedPoolFee, address(3), false
        );

        (address target, bool zeroForOne) = uniswapV3Exposed.decodeData(data);

        assertEq(target, address(3));
        assertEq(zeroForOne, false);
    }

    function testGetTransferData() public {
        bytes memory params = "";

        (
            TransferManager.TransferType transferType,
            address receiver,
            address tokenIn,
            address tokenOut,
            bool outputToRouter
        ) = uniswapV3Exposed.getTransferData(params);

        assertEq(uint8(transferType), uint8(TransferManager.TransferType.None));
        assertEq(receiver, address(0));
        assertEq(tokenIn, address(0));
        assertEq(tokenOut, address(0));
        assertEq(outputToRouter, false);
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
        (, address receiver, address tokenIn) =
            uniswapV3Exposed.getCallbackTransferData(callbackData);

        assertEq(receiver, address(this));
        assertEq(tokenIn, WETH_ADDR);
    }

    function testSwapIntegration() public {
        uint256 amountIn = 10 ** 18;
        deal(WETH_ADDR, address(uniswapV3Exposed), amountIn);

        uint256 expAmountOut = 1205_128428842122129186; //Swap 1 WETH for 1205.12 DAI
        bool zeroForOne = false;

        bytes memory data =
            encodeUniswapV3Swap(WETH_ADDR, DAI_ADDR, DAI_WETH_USV3, zeroForOne);

        uint256 balanceBefore = IERC20(DAI_ADDR).balanceOf(address(this));
        uniswapV3Exposed.swap(amountIn, data, address(this));
        uint256 amountOut =
            IERC20(DAI_ADDR).balanceOf(address(this)) - balanceBefore;

        assertGe(amountOut, expAmountOut);
        assertEq(IERC20(WETH_ADDR).balanceOf(address(uniswapV3Exposed)), 0);
        assertGe(IERC20(DAI_ADDR).balanceOf(address(this)), expAmountOut);
    }

    function testDecodeParamsInvalidDataLength() public {
        bytes memory invalidParams = abi.encodePacked(
            WETH_ADDR,
            DAI_ADDR,
            uint24(500),
            TransferManager.TransferType.Transfer,
            address(3),
            false
        );

        vm.expectRevert(UniswapV3Executor__InvalidDataLength.selector);
        uniswapV3Exposed.decodeData(invalidParams);
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

// Fake UniswapV3-compatible pool used as an exploit probe.
//
// Triggers uniswapV3SwapCallback with amount0Delta = amountIn/2 (intentionally
// less than the declared amountIn). The pool keeps the WETH and returns nothing to
// the recipient.
contract FakeMaliciousUniV3Pool {
    using SafeERC20 for IERC20;

    address public immutable tychoRouter;

    constructor(address tychoRouter_) {
        tychoRouter = tychoRouter_;
    }

    function swap(
        address, /* recipient */
        bool, /* zeroForOne */
        int256 amountSpecified,
        uint160, /* sqrtPriceLimitX96 */
        bytes calldata data // protocolData: tokenIn|tokenOut|fee|target|zeroForOne
    ) external returns (int256, int256) {
        // Claim only half of amountIn so the old cyclic adjustment
        bytes memory callbackPayload = abi.encodeWithSelector(
            bytes4(0xfa461e33), // callback selector
            // This must be amount / 2 in order for the exploit to work
            // otherwise, we get an unexpected input delta
            int256(uint256(amountSpecified) / 2), // amount0 delta
            int256(0), // amount1 delta
            data // protocol data
        );

        (bool success,) = tychoRouter.call(callbackPayload);
        require(success, "callback failed");

        // Pool keeps the WETH — no transfer back to recipient.
        return (amountSpecified, 0);
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
        UniswapV3ExecutorExposed basePancakeV3Exposed =
            new UniswapV3ExecutorExposed();

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

    function testCyclicVaultSwapPartialCallbackDrainReverts() public {
        // An exploit where the pool encodes exactly half of the input amount to take
        // during the callback. Before our fix, the numbers fit together nicely,
        // creating an expected delta amount, allowing the malicious pool to steal
        // router funds unnoticed.
        //
        // The amount in is 1 ether.
        // The pool uses 0.5 ether, and transfers nothing out.
        // This results in delta(WETH) = - 0.5
        // The router balance after the swap is 0.5 ether.
        //
        // Before the fix, our cyclic adjustment was:
        // balanceAfterSwap = balanceAfterSwap + amountIn
        //                  = 0.5 + 1
        //                  = 1.5
        //
        // Which means:
        // amountOut = balanceAfterSwap - balanceBeforeSwap;
        //           = 1.5 - 1;
        //           = 0.5
        //
        // Then, when transferring the output token (0.5) back to the user,
        // this results in an input delta of 1 ether, which is allowed, since this is
        // exactly the amount in.
        //
        // After our fix we no longer rely on pool-encoded transfer amounts, so this
        // is no longer possible.
        uint256 amountIn = 1 ether;

        // Seed the router with WETH (simulates tokens from other users).
        deal(WETH_ADDR, tychoRouterAddr, amountIn);
        uint256 routerWethBefore = IERC20(WETH_ADDR).balanceOf(tychoRouterAddr);

        vm.startPrank(ALICE);

        FakeMaliciousUniV3Pool fakePool =
            new FakeMaliciousUniV3Pool(tychoRouterAddr);

        // protocolData layout: tokenIn (20) | tokenOut (20) | fee (3) | target
        // (20) | zeroForOne (1). tokenOut == tokenIn triggers cyclic detection.
        bytes memory protocolData = abi.encodePacked(
            WETH_ADDR, WETH_ADDR, uint24(3000), address(fakePool), false
        );
        bytes memory swapData =
            encodeSingleSwap(address(usv3Executor), protocolData);

        // fakePool triggers callback with amount0Delta = amountIn/2.
        // After the fix amountOut = 0, which is below minAmountOut = 1.
        vm.expectRevert(
            abi.encodeWithSelector(
                TychoRouter__NegativeSlippage.selector, uint256(0), uint256(1)
            )
        );
        tychoRouter.singleSwapUsingVault(
            amountIn,
            WETH_ADDR,
            WETH_ADDR,
            1,
            tychoRouterAddr,
            noClientFee(),
            swapData
        );

        vm.stopPrank();

        // EVM revert rolls back the callback transfer — no WETH was stolen.
        assertEq(
            IERC20(WETH_ADDR).balanceOf(tychoRouterAddr),
            routerWethBefore,
            "router WETH must be unchanged after the reverted drain attempt"
        );
        assertEq(
            IERC20(WETH_ADDR).balanceOf(address(fakePool)),
            0,
            "fake pool must hold nothing after the reverted drain attempt"
        );
    }
}
