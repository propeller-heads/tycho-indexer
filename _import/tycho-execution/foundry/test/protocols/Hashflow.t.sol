// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/HashflowExecutor.sol";
import {Constants} from "../Constants.sol";
import "forge-std/Test.sol";

contract HashflowUtils is Test {
    constructor() {}

    function encodeRfqtQuote(
        IHashflowRouter.RFQTQuote memory quote,
        bool approvalNeeded,
        RestrictTransferFrom.TransferType transferType
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            uint8(transferType), // transferType (1 byte)
            approvalNeeded, // needsApproval (1 byte)
            quote.pool, // pool (20 bytes)
            quote.externalAccount, // externalAccount (20 bytes)
            quote.trader, // trader (20 bytes)
            quote.effectiveTrader, // effectiveTrader (20 bytes)
            quote.baseToken, // baseToken (20 bytes)
            quote.quoteToken, // quoteToken (20 bytes)
            quote.baseTokenAmount, // baseTokenAmount (32 bytes)
            quote.quoteTokenAmount, // quoteTokenAmount (32 bytes)
            quote.quoteExpiry, // quoteExpiry (32 bytes)
            quote.nonce, // nonce (32 bytes)
            quote.txid, // txid (32 bytes)
            quote.signature // signature data
        );
    }

    function encodeRfqtQuoteWithDefaults(IHashflowRouter.RFQTQuote memory quote)
        internal
        pure
        returns (bytes memory)
    {
        return
            encodeRfqtQuote(quote, true, RestrictTransferFrom.TransferType.None);
    }
}

contract HashflowExecutorECR20Test is Constants, HashflowUtils {
    using SafeERC20 for IERC20;

    HashflowExecutorExposed executor;
    uint256 forkBlock;

    IERC20 WETH = IERC20(WETH_ADDR);
    IERC20 USDC = IERC20(USDC_ADDR);

    function setUp() public {
        forkBlock = 23124977; // Using expiry date: 1755001853, ECR20
        vm.createSelectFork("mainnet", forkBlock);
        executor = new HashflowExecutorExposed(HASHFLOW_ROUTER, PERMIT2_ADDRESS);
    }

    function testDecodeParams() public view {
        IHashflowRouter.RFQTQuote memory expected_quote = rfqtQuote();
        bytes memory encodedQuote = encodeRfqtQuoteWithDefaults(expected_quote);
        (
            IHashflowRouter.RFQTQuote memory quote,
            bool approvalNeeded,
            RestrictTransferFrom.TransferType transferType
        ) = executor.decodeData(encodedQuote);

        assertEq(quote.pool, expected_quote.pool, "pool mismatch");
        assertEq(
            quote.externalAccount,
            expected_quote.externalAccount,
            "externalAccount mismatch"
        );
        assertEq(quote.trader, expected_quote.trader, "trader mismatch");
        assertEq(
            quote.effectiveTrader,
            expected_quote.effectiveTrader,
            "effectiveTrader mismatch"
        );
        assertEq(
            quote.baseToken, expected_quote.baseToken, "baseToken mismatch"
        );
        assertEq(
            quote.quoteToken, expected_quote.quoteToken, "quoteToken mismatch"
        );
        assertEq(
            quote.effectiveBaseTokenAmount,
            expected_quote.effectiveBaseTokenAmount,
            "effectiveBaseTokenAmount mismatch"
        );
        assertEq(
            quote.baseTokenAmount,
            expected_quote.baseTokenAmount,
            "baseTokenAmount mismatch"
        );
        assertEq(
            quote.quoteTokenAmount,
            expected_quote.quoteTokenAmount,
            "quoteTokenAmount mismatch"
        );
        assertEq(
            quote.quoteExpiry,
            expected_quote.quoteExpiry,
            "quoteExpiry mismatch"
        );
        assertEq(quote.nonce, expected_quote.nonce, "nonce mismatch");
        assertEq(quote.txid, expected_quote.txid, "txid mismatch");
        assertEq(
            quote.signature, expected_quote.signature, "signature mismatch"
        );
        assertEq(approvalNeeded, true, "Approval flag mismatch");
        assertEq(
            uint8(transferType),
            uint8(RestrictTransferFrom.TransferType.None),
            "Transfer type mismatch"
        );
    }

    function testDecodeParamsInvalidDataLength() public {
        bytes memory invalidData = new bytes(10);
        vm.expectRevert(HashflowExecutor__InvalidDataLength.selector);
        executor.decodeData(invalidData);
    }

    function testSwapNoSlippage() public {
        address trader = address(executor);
        IHashflowRouter.RFQTQuote memory quote = rfqtQuote();
        uint256 amountIn = quote.baseTokenAmount;
        bytes memory encodedQuote = encodeRfqtQuoteWithDefaults(quote);

        deal(USDC_ADDR, address(executor), amountIn);
        uint256 balanceBefore = WETH.balanceOf(trader);

        vm.prank(trader);
        uint256 amountOut = executor.swap(amountIn, encodedQuote);

        uint256 balanceAfter = WETH.balanceOf(trader);
        assertGt(balanceAfter, balanceBefore);
        assertEq(balanceAfter - balanceBefore, amountOut);
        assertEq(amountOut, quote.quoteTokenAmount);
    }

    function testSwapRouterAmountUnderQuoteAmount() public {
        address trader = address(executor);
        IHashflowRouter.RFQTQuote memory quote = rfqtQuote();
        uint256 amountIn = quote.baseTokenAmount - 1;
        bytes memory encodedQuote = encodeRfqtQuoteWithDefaults(quote);

        deal(USDC_ADDR, address(executor), amountIn);
        uint256 balanceBefore = WETH.balanceOf(trader);

        vm.prank(trader);
        uint256 amountOut = executor.swap(amountIn, encodedQuote);

        uint256 balanceAfter = WETH.balanceOf(trader);
        assertGt(balanceAfter, balanceBefore);
        assertEq(balanceAfter - balanceBefore, amountOut);
        assertLt(amountOut, quote.quoteTokenAmount);
    }

    function testSwapRouterAmountOverQuoteAmount() public {
        address trader = address(executor);
        IHashflowRouter.RFQTQuote memory quote = rfqtQuote();
        uint256 amountIn = quote.baseTokenAmount + 1;
        bytes memory encodedQuote = encodeRfqtQuoteWithDefaults(quote);

        deal(USDC_ADDR, address(executor), amountIn);
        uint256 balanceBefore = WETH.balanceOf(trader);

        vm.prank(trader);
        uint256 amountOut = executor.swap(amountIn, encodedQuote);

        uint256 balanceAfter = WETH.balanceOf(trader);
        assertGt(balanceAfter, balanceBefore);
        assertEq(balanceAfter - balanceBefore, amountOut);
        assertEq(amountOut, quote.quoteTokenAmount);
    }

    function rfqtQuote()
        internal
        view
        returns (IHashflowRouter.RFQTQuote memory)
    {
        return IHashflowRouter.RFQTQuote({
            pool: address(0x4cE18FD7b44F40Aebd6911362d3AC25F14D5007f),
            externalAccount: address(0x50C03775C8E5b6227F1E00C4b3e479b4A7C57983),
            trader: address(executor),
            effectiveTrader: address(ALICE),
            baseToken: USDC_ADDR,
            quoteToken: WETH_ADDR,
            effectiveBaseTokenAmount: 0,
            baseTokenAmount: 100,
            quoteTokenAmount: 23224549208,
            quoteExpiry: 1755001853,
            nonce: 1755001793084,
            txid: bytes32(
                uint256(
                    0x12500006400064000000174813b960ffffffffffffff00293fdb4569fe760000
                )
            ),
            signature: hex"5b26977fecaf794c3d6900b9523b9632b5c62623f92732347dc9f24d8b5c4d611f5d733bbe82b594b6b47ab8aa1923c9f6b8aa66ef822ce412a767200f1520e11b"
        });
    }
}

contract HashflowExecutorNativeTest is Constants, HashflowUtils {
    using SafeERC20 for IERC20;

    HashflowExecutorExposed executor;
    uint256 forkBlock;

    IERC20 WETH = IERC20(WETH_ADDR);
    IERC20 USDC = IERC20(USDC_ADDR);

    function setUp() public {
        forkBlock = 23125321; // Using expiry date: 1755006017, Native
        vm.createSelectFork("mainnet", forkBlock);
        executor = new HashflowExecutorExposed(HASHFLOW_ROUTER, PERMIT2_ADDRESS);
    }

    function testSwapNoSlippage() public {
        address trader = address(executor);
        IHashflowRouter.RFQTQuote memory quote = rfqtQuote();
        uint256 amountIn = quote.baseTokenAmount;
        bytes memory encodedQuote = encodeRfqtQuoteWithDefaults(quote);

        vm.deal(address(executor), amountIn);
        uint256 balanceBefore = USDC.balanceOf(trader);

        vm.prank(trader);
        uint256 amountOut = executor.swap(amountIn, encodedQuote);

        uint256 balanceAfter = USDC.balanceOf(trader);
        assertGt(balanceAfter, balanceBefore);
        assertEq(balanceAfter - balanceBefore, amountOut);
        assertEq(amountOut, quote.quoteTokenAmount);
    }

    function rfqtQuote()
        internal
        view
        returns (IHashflowRouter.RFQTQuote memory)
    {
        return IHashflowRouter.RFQTQuote({
            pool: address(0x51199bE500A8c59262478b621B1096F17638dc6F),
            externalAccount: address(0xCe79b081c0c924cb67848723ed3057234d10FC6b),
            trader: address(executor),
            effectiveTrader: address(ALICE),
            baseToken: address(0x0000000000000000000000000000000000000000),
            quoteToken: USDC_ADDR,
            effectiveBaseTokenAmount: 0,
            baseTokenAmount: 10000000000000000,
            quoteTokenAmount: 43930745,
            quoteExpiry: 1755006017,
            nonce: 1755005977455,
            txid: bytes32(
                uint256(
                    0x1250000640006400019071ef777818ffffffffffffff0029401b1bc51da00000
                )
            ),
            signature: hex"4c3554c928e4b15cd53d1047aee69a66103effa5107047b84949e48460b6978f25da9ad5b9ed31aa9ab2130e597fabea872f14b8c1b166ea079413cbaf2f4b4c1c"
        });
    }
}

contract HashflowExecutorExposed is HashflowExecutor {
    constructor(address _hashflowRouter, address _permit2)
        HashflowExecutor(_hashflowRouter, _permit2)
    {}

    function decodeData(bytes calldata data)
        external
        pure
        returns (
            IHashflowRouter.RFQTQuote memory quote,
            bool approvalNeeded,
            TransferType transferType
        )
    {
        return _decodeData(data);
    }
}

contract TychoRouterSingleSwapTestForHashflow is TychoRouterTestSetup {
    function getForkBlock() public pure override returns (uint256) {
        return 23175437;
    }

    function testHashflowIntegration() public {
        // Performs a swap from USDC to WBTC using Hashflow RFQ
        //
        //   USDC ───(Hashflow RFQ)──> WBTC

        // The Hashflow order expects:
        // - 4308094737 USDC input -> 3714751 WBTC output

        uint256 amountIn = 4308094737;
        uint256 expectedAmountOut = 3714751;
        deal(USDC_ADDR, ALICE, amountIn);
        uint256 balanceBefore = IERC20(WBTC_ADDR).balanceOf(ALICE);

        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(tychoRouterAddr, type(uint256).max);
        bytes memory callData = loadCallDataFromFile("test_hashflow");
        (bool success,) = tychoRouterAddr.call(callData);

        vm.stopPrank();

        uint256 balanceAfter = IERC20(WBTC_ADDR).balanceOf(ALICE);

        assertTrue(success, "Call Failed");
        assertEq(balanceAfter - balanceBefore, expectedAmountOut);
        assertEq(IERC20(WETH_ADDR).balanceOf(tychoRouterAddr), 0);
    }
}
