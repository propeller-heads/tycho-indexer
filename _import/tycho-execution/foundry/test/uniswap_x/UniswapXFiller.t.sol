// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "@src/uniswap_x/UniswapXFiller.sol";
import "../TychoRouterTestSetup.sol";

contract UniswapXFillerTest is Test, TychoRouterTestSetup {
    address EXECUTOR = address(0xCe79b081c0c924cb67848723ed3057234d10FC6b);
    address REACTOR = address(0x00000011F84B9aa48e5f8aA8B9897600006289Be);

    UniswapXFiller filler;
    address fillerAddr;

    event CallbackVerifierSet(address indexed callbackVerifier);
    event Withdrawal(
        address indexed token, uint256 amount, address indexed receiver
    );

    function getForkBlock() public pure override returns (uint256) {
        return 22880493;
    }

    function fillerSetup() public {
        vm.startPrank(ADMIN);
        filler = new UniswapXFiller(tychoRouterAddr, REACTOR, address(0));
        fillerAddr = address(filler);
        filler.grantRole(keccak256("EXECUTOR_ROLE"), EXECUTOR);
        vm.stopPrank();
    }

    function testTychoAddressZeroTychoRouter() public {
        vm.expectRevert(UniswapXFiller__AddressZero.selector);
        filler = new UniswapXFiller(address(0), REACTOR, address(0));
    }

    function testTychoAddressZeroReactor() public {
        vm.expectRevert(UniswapXFiller__AddressZero.selector);
        filler = new UniswapXFiller(tychoRouterAddr, address(0), address(0));
    }

    function testCallback() public {
        fillerSetup();
        uint256 amountIn = 10 ** 18;
        uint256 amountOut = 1847751195973566072891;
        bool zeroForOne = false;
        bytes memory protocolData = abi.encodePacked(
            WETH_ADDR,
            WETH_DAI_POOL,
            address(filler),
            zeroForOne,
            RestrictTransferFrom.TransferType.TransferFrom
        );

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        bytes memory tychoRouterData = abi.encodeWithSelector(
            tychoRouter.singleSwap.selector,
            amountIn,
            WETH_ADDR,
            DAI_ADDR,
            2008817438608734439722,
            false,
            false,
            address(filler),
            true,
            swap
        );

        bytes memory callbackData =
            abi.encodePacked(true, true, tychoRouterData);

        deal(WETH_ADDR, address(filler), amountIn);

        ResolvedOrder[] memory orders = new ResolvedOrder[](1);
        OutputToken[] memory outputs = new OutputToken[](1);
        outputs[0] = OutputToken({
            token: address(DAI_ADDR),
            amount: 1847751195973566072891,
            recipient: BOB
        });
        // Irrelevant fields for this test - we only need token output
        // info for the sake of testing.
        orders[0] = ResolvedOrder({
            info: OrderInfo({
                reactor: address(0),
                swapper: address(0),
                nonce: 0,
                deadline: 0,
                additionalValidationContract: address(0),
                additionalValidationData: ""
            }),
            input: InputToken({
                token: address(WETH_ADDR),
                amount: amountIn,
                maxAmount: amountIn
            }),
            outputs: outputs,
            sig: "",
            hash: ""
        });

        vm.startPrank(REACTOR);
        filler.reactorCallback(orders, callbackData);
        vm.stopPrank();

        // Check that the funds are in the filler at the end of the function call
        uint256 finalBalance = IERC20(DAI_ADDR).balanceOf(address(filler));
        assertGe(finalBalance, amountOut);

        // Check that the proper approval was set
        vm.startPrank(REACTOR);
        IERC20(DAI_ADDR).transferFrom(address(filler), BOB, amountOut);
        vm.stopPrank();
        assertGe(IERC20(DAI_ADDR).balanceOf(BOB), amountOut);
    }

    function testExecuteIntegration() public {
        fillerSetup();

        // Set to time with no more exclusivity penalty for not being exclusive filler
        vm.warp(1752050415);

        deal(
            DAI_ADDR,
            address(0xD213e6F6dCB2DBaC03FA28b893F6dA1BD822e852),
            2000 ether
        );

        uint256 amountIn = 2000000000000000000000;

        vm.startPrank(address(0xD213e6F6dCB2DBaC03FA28b893F6dA1BD822e852));
        // Approve Permit2
        IERC20(DAI_ADDR).approve(
            address(0x000000000022D473030F116dDEE9F6B43aC78BA3), amountIn
        );
        vm.stopPrank();

        // Tx 0x005d7b150017ba1b59d2f99395ccae7bda9b739938ade4e509817e32760aaf9d
        // Calldata generated using rust test `test_sequential_swap_usx`

        SignedOrder memory order = SignedOrder({
            order: hex"000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000001000000000000000000000000004449cd34d1eb1fedcf02a1be3834ffde8e6a61800000000000000000000000006b175474e89094c44da98b954eedeac495271d0f00000000000000000000000000000000000000000000006c6b935b8bbd40000000000000000000000000000000000000000000000000006c6b935b8bbd40000000000000000000000000000000000000000000000000000000000000000001e00000000000000000000000000000000000000000000000000000000000000280000000000000000000000000000000000000000000000000000000000000038000000000000000000000000000000011f84b9aa48e5f8aa8b9897600006289be000000000000000000000000d213e6f6dcb2dbac03fa28b893f6da1bd822e8520468320351debb1ddbfb032a239d699e3d54e3ce2b6e1037cd836a784c80b60100000000000000000000000000000000000000000000000000000000686e2bf9000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec70000000000000000000000000000000000000000000000000000000076f9f4870000000000000000000000000000000000000000000000000000000076566300000000000000000000000000d213e6f6dcb2dbac03fa28b893f6da1bd822e85200000000000000000000000000000000000000000000000000000000686e2aee00000000000000000000000000000000000000000000000000000000686e2b2a000000000000000000000000ce79b081c0c924cb67848723ed3057234d10fc6b0000000000000000000000000000000000000000000000000000000000000064000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000007727b5f40000000000000000000000000000000000000000000000000000000000000041a2d261cd4c8930428260f18b55e3036024bac68d58cb2ee6161e6395b0984b827104158713d44ddc4e14d852b48d93d95a4e60b8d5be1ef431c1e82d2f76a4111b00000000000000000000000000000000000000000000000000000000000000",
            sig: hex"f4cc5734820e4ee08519045c83a25b75687756053b3d6c0fda2141380dfa6ef17b40f64d9279f237e96982c6ba53a202e01a4358fd66e027c9bdf200d5626f441c"
        });

        bytes memory callbackData =
            loadCallDataFromFile("test_sequential_swap_usx");

        vm.startPrank(EXECUTOR);
        filler.execute(order, callbackData);
        vm.stopPrank();
    }

    function testExecute() public {
        fillerSetup();

        // Overwrite block so signature doesn't expire.
        vm.rollFork(22788691);

        // tx: 0x5b602b7d0a37e241bd032a907b9ddf314e9f2fc2104fd91cb55bdb3d8dfe4e9c
        // 0.2 WBTC -> USDC
        SignedOrder memory order = SignedOrder({
            order: hex"000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000001000000000000000000000000004449cd34d1eb1fedcf02a1be3834ffde8e6a61800000000000000000000000002260fac5e5542a773aa44fbcfedf7c193bc2c5990000000000000000000000000000000000000000000000000000000001312d000000000000000000000000000000000000000000000000000000000001312d0000000000000000000000000000000000000000000000000000000000000001e00000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000042000000000000000000000000000000011f84b9aa48e5f8aa8b9897600006289be0000000000000000000000000d1100e55ef6c4e5800f4624b1e6121d798eb696046832163cef9c09382cf582bb878b37a42933ea2bdf33757942ab2747b3500100000000000000000000000000000000000000000000000000000000685d4150000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000004f921447c00000000000000000000000000000000000000000000000000000004f1464dea0000000000000000000000000d1100e55ef6c4e5800f4624b1e6121d798eb696000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000000000000000000000000000000000000330d86400000000000000000000000000000000000000000000000000000000032bce2600000000000000000000000027213e28d7fda5c57fe9e5dd923818dbccf71c4700000000000000000000000000000000000000000000000000000000685d407600000000000000000000000000000000000000000000000000000000685d40b2000000000000000000000000225a38bc71102999dd13478bfabd7c4d53f2dc170000000000000000000000000000000000000000000000000000000000000064000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000004fb7f8815000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000417067afde0759ae3653dad5d412519f488b6e9ed8955b3e3b8606e85c0198a9d71075295d33fe84b5ccc9c2d38a7ea79d7fad68128a37cabc5557342756a4e8311b00000000000000000000000000000000000000000000000000000000000000",
            sig: hex"41b7a696a04f897d1e4ccaf88136092169c2874242d55c3fe4c028125efe95340f5ce764b9dce9d2cae241d97ceb515d3f1739972ca884ed51b2870045438c3a1c"
        });

        uint256 amountIn = 0.2 * 10 ** 8;
        bool zeroForOne = true;
        bytes memory protocolData = abi.encodePacked(
            WBTC_ADDR,
            USDC_WBTC_POOL,
            fillerAddr,
            zeroForOne,
            RestrictTransferFrom.TransferType.TransferFrom
        );

        bytes memory swap =
            encodeSingleSwap(address(usv2Executor), protocolData);

        bytes memory tychoRouterData = abi.encodeWithSelector(
            tychoRouter.singleSwap.selector,
            amountIn,
            WBTC_ADDR,
            USDC_ADDR,
            1,
            false,
            false,
            fillerAddr,
            true,
            swap
        );

        bytes memory callbackData = abi.encodePacked(
            true, // tokenIn approval needed
            true, // tokenOut approval needed
            tychoRouterData
        );

        vm.startPrank(address(filler));
        IERC20(WBTC_ADDR).approve(tychoRouterAddr, amountIn);
        vm.stopPrank();

        // This is a hack because the tx we are trying to replicate returns a looooot more USDC than what the uni v2 pool does at this point
        // 21613301393 is the difference and 54068100 is the fee
        deal(USDC_ADDR, address(filler), 21613301393 + 54068100);

        vm.startPrank(EXECUTOR);
        filler.execute(order, callbackData);
        console.logUint(IERC20(USDC_ADDR).balanceOf(address(filler)));
        vm.stopPrank();
    }

    function testWithdrawNative() public {
        fillerSetup();
        vm.startPrank(ADMIN);
        // Send 100 ether to filler
        assertEq(fillerAddr.balance, 0);
        assertEq(ADMIN.balance, 0);
        vm.deal(fillerAddr, 100 ether);
        vm.expectEmit();
        emit Withdrawal(address(0), 100 ether, ADMIN);
        filler.withdrawNative(ADMIN);
        assertEq(fillerAddr.balance, 0);
        assertEq(ADMIN.balance, 100 ether);
        vm.stopPrank();
    }

    function testWithdrawNativeAddressZero() public {
        fillerSetup();
        vm.deal(fillerAddr, 100 ether);
        vm.startPrank(ADMIN);
        vm.expectRevert(UniswapXFiller__AddressZero.selector);
        filler.withdrawNative(address(0));
        vm.stopPrank();
    }

    function testWithdrawNativeMissingRole() public {
        fillerSetup();
        vm.deal(fillerAddr, 100 ether);
        // Not role ADMIN
        vm.startPrank(BOB);
        vm.expectRevert();
        filler.withdrawNative(ADMIN);
        vm.stopPrank();
    }

    function testWithdrawERC20Tokens() public {
        fillerSetup();

        IERC20[] memory tokens = new IERC20[](2);
        tokens[0] = IERC20(WETH_ADDR);
        tokens[1] = IERC20(USDC_ADDR);
        for (uint256 i = 0; i < tokens.length; i++) {
            deal(address(tokens[i]), fillerAddr, 100 ether);
        }

        vm.startPrank(ADMIN);
        filler.withdraw(tokens, ADMIN);

        // Check balances after withdrawing
        for (uint256 i = 0; i < tokens.length; i++) {
            // slither-disable-next-line calls-loop
            assertEq(tokens[i].balanceOf(fillerAddr), 0);
            // slither-disable-next-line calls-loop
            assertEq(tokens[i].balanceOf(ADMIN), 100 ether);
        }
        vm.stopPrank();
    }

    function testWithdrawERC20TokensAddressZero() public {
        fillerSetup();

        IERC20[] memory tokens = new IERC20[](2);
        tokens[0] = IERC20(WETH_ADDR);
        tokens[1] = IERC20(USDC_ADDR);
        for (uint256 i = 0; i < tokens.length; i++) {
            deal(address(tokens[i]), fillerAddr, 100 ether);
        }

        vm.startPrank(ADMIN);
        vm.expectRevert(UniswapXFiller__AddressZero.selector);
        filler.withdraw(tokens, address(0));
        vm.stopPrank();
    }

    function testWithdrawERC20TokensAddressMissingRole() public {
        fillerSetup();

        IERC20[] memory tokens = new IERC20[](2);
        tokens[0] = IERC20(WETH_ADDR);
        tokens[1] = IERC20(USDC_ADDR);
        for (uint256 i = 0; i < tokens.length; i++) {
            deal(address(tokens[i]), fillerAddr, 100 ether);
        }

        // Not role ADMIN
        vm.startPrank(BOB);
        vm.expectRevert();
        filler.withdraw(tokens, ADMIN);
        vm.stopPrank();
    }
}
