// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./SwapExecutor.t.sol";
import "../src/curve/CurveSwapExecutor.sol";

contract CurveSwapExecutorExposed is CurveSwapExecutor {
    function decodeParams(bytes calldata data)
        external
        pure
        returns (
            IERC20 tokenOut,
            address target,
            address receiver,
            uint8 poolType,
            int128 i,
            int128 j,
            bool tokenApprovalNeeded
        )
    {
        return _decodeParams(data);
    }
}

contract CurveSwapExecutorPayable is CurveSwapExecutor {
    receive() external payable {}
}

interface ILendingPool {
    function deposit(
        address asset,
        uint256 amount,
        address onBehalfOf,
        uint16 referralCode
    ) external;

    function withdraw(address asset, uint256 amount, address to)
        external
        returns (uint256);
}

contract TestCurveSwapExecutor is SwapExecutorTest {
    CurveSwapExecutor swapMethod;
    address swapMethodAddress;
    // type 0 pool
    address aDAI_ADDR = 0x028171bCA77440897B824Ca71D1c56caC55b68A3;
    address aUSDC_ADDR = 0xBcca60bB61934080951369a648Fb03DF4F96263C;
    IERC20 aDAI = IERC20(aDAI_ADDR);
    IERC20 aUSDC = IERC20(aUSDC_ADDR);
    address AAVE_POOL = 0xDeBF20617708857ebe4F679508E7b7863a8A8EeE;

    // type 1 - 3pool
    IERC20 DAI = IERC20(DAI_ADDR);
    IERC20 USDC = IERC20(USDC_ADDR);
    address THREE_POOL = 0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7;

    // type 3 - tricrypto case
    IERC20 WETH = IERC20(WETH_ADDR);
    IERC20 WBTC = IERC20(WBTC_ADDR);
    address TRICRYPTO_POOL = 0xD51a44d3FaE010294C616388b506AcdA1bfAAE46;

    // type 4 - stETH
    address stETH_ADDR = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;
    IERC20 stETH = IERC20(stETH_ADDR);
    address stETH_POOL = 0xDC24316b9AE028F1497c275EB9192a3Ea0f67022;

    // type 5 - LUSD
    address LUSD_ADDR = 0x5f98805A4E8be255a32880FDeC7F6728C6568bA0;
    IERC20 LUSD = IERC20(LUSD_ADDR);
    IERC20 USDT = IERC20(USDT_ADDR);
    address LUSD_POOL = 0xEd279fDD11cA84bEef15AF5D39BB4d4bEE23F0cA;

    // type 6 - compound
    address CPOOL = 0xA2B47E3D5c44877cca798226B7B8118F9BFb7A56;

    // type 7
    address LDO_POOL = 0x9409280DC1e6D33AB7A8C6EC03e5763FB61772B5;
    IERC20 LDO = IERC20(LDO_ADDR);

    // type 8
    address CRV_POOL = 0x8301AE4fc9c624d1D396cbDAa1ed877821D7C511;
    IERC20 CRV = IERC20(CRV_ADDR);

    function setUp() public {
        //Fork
        uint256 forkBlock = 16000000;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);

        //Setup
        swapMethod = new CurveSwapExecutor();
        swapMethodAddress = address(swapMethod);
        vm.makePersistent(swapMethodAddress);
    }

    // foundry deal doesn't work with the atokens:
    // https://github.com/foundry-rs/forge-std/issues/140
    function dealAaveDai() internal {
        deal(DAI_ADDR, swapMethodAddress, 100_000 * 10 ** 18);
        ILendingPool aave =
            ILendingPool(0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9);

        vm.startPrank(swapMethodAddress);
        DAI.approve(address(aave), type(uint256).max);
        aave.deposit(DAI_ADDR, 100_000 * 10 ** 18, swapMethodAddress, 0);
        vm.stopPrank();
    }

    function testSwapType0() public {
        dealAaveDai();
        IERC20[] memory tokens = twoTokens(aDAI_ADDR, aUSDC_ADDR);
        uint256 expAmountOut = 999647;
        address receiver = bob;
        bytes memory data =
            getDataCurve(tokens[1], AAVE_POOL, receiver, 1, 0, 1, true);
        uint256 amountOut = swapMethod.swap(10 ** 18, data);

        uint256 finalBalance = aUSDC.balanceOf(receiver);
        assertGe(finalBalance, expAmountOut);
        assertEq(amountOut, expAmountOut);
    }

    // 3pool
    function testSwapType1() public {
        deal(DAI_ADDR, swapMethodAddress, 10_000 * 10 ** 18);
        IERC20[] memory tokens = twoTokens(DAI_ADDR, USDC_ADDR);
        uint256 expAmountOut = 999963;
        address receiver = bob;

        bytes memory data =
            getDataCurve(tokens[1], THREE_POOL, receiver, 1, 0, 1, true);

        uint256 amountOut = swapMethod.swap(10 ** 18, data);

        uint256 finalBalance = USDC.balanceOf(receiver);
        assertGe(finalBalance, expAmountOut);
        assertEq(amountOut, expAmountOut);
    }

    // tricrypto
    function testSwapType3() public {
        deal(USDT_ADDR, swapMethodAddress, 10_000 * 10 ** 6);
        IERC20[] memory tokens = twoTokens(USDT_ADDR, WBTC_ADDR);
        uint256 expAmountOut = 60232482;
        address receiver = bob;

        bytes memory data =
            getDataCurve(tokens[1], TRICRYPTO_POOL, receiver, 3, 0, 1, true);

        uint256 amountOut = swapMethod.swap(10_000 * 10 ** 6, data);

        uint256 finalBalance = WBTC.balanceOf(receiver);
        assertGe(finalBalance, expAmountOut);
        assertEq(amountOut, expAmountOut);
    }

    // stETH/ETH pool
    function testSwapType4() public {
        CurveSwapExecutorPayable swapMethodPayable =
            new CurveSwapExecutorPayable();
        address swapMethodPayableAddress = address(swapMethodPayable);
        deal(WETH_ADDR, swapMethodPayableAddress, 100 * 10 ** 18);
        IERC20[] memory tokens = twoTokens(WETH_ADDR, stETH_ADDR);
        uint256 expAmountOut = 1011264689661846353;
        bytes memory data = getDataCurve(
            tokens[1], stETH_POOL, swapMethodPayableAddress, 4, 0, 1, false
        );

        vm.prank(swapMethodPayableAddress);
        uint256 amountOut = swapMethodPayable.swap(10 ** 18, data);

        uint256 finalBalance = stETH.balanceOf(swapMethodPayableAddress);
        assertGe(finalBalance, expAmountOut);
        // There is something weird with
        // stETH that it gives me 1 Wei more here sometimes
        assertGe(amountOut, expAmountOut);

        // part 2 swap back stETH
        tokens = twoTokens(stETH_ADDR, WETH_ADDR);
        expAmountOut = 988069860569702379;
        address receiver = bob;

        data = getDataCurve(tokens[1], stETH_POOL, receiver, 4, 1, 0, true);
        uint256 initialBalance = WETH.balanceOf(receiver);

        amountOut = swapMethodPayable.swap(10 ** 18, data);

        finalBalance = WETH.balanceOf(receiver) - initialBalance;
        assertGe(finalBalance, expAmountOut);
        assertEq(amountOut, expAmountOut);
    }

    // // metapool - LUSD
    function testSwapType5() public {
        deal(LUSD_ADDR, swapMethodAddress, 10_000 * 10 ** 18);
        IERC20[] memory tokens = twoTokens(LUSD_ADDR, USDT_ADDR);
        uint256 expAmountOut = 1035119;
        address receiver = bob;

        bytes memory data =
            getDataCurve(tokens[1], LUSD_POOL, receiver, 5, 0, 3, true);

        uint256 amountOut = swapMethod.swap(10 ** 18, data);

        uint256 finalBalance = USDT.balanceOf(receiver);
        assertGe(finalBalance, expAmountOut);
        assertEq(amountOut, expAmountOut);
    }

    // Compound
    function testSwapType6() public {
        deal(DAI_ADDR, swapMethodAddress, 10_000 * 10 ** 18);
        IERC20[] memory tokens = twoTokens(DAI_ADDR, USDC_ADDR);
        uint256 expAmountOut = 999430;
        address receiver = bob;

        bytes memory data =
            getDataCurve(tokens[1], CPOOL, receiver, 6, 0, 1, true);

        uint256 amountOut = swapMethod.swap(10 ** 18, data);

        uint256 finalBalance = USDC.balanceOf(receiver);
        assertGe(finalBalance, expAmountOut);
        assertEq(amountOut, expAmountOut);
    }

    // Curve v2
    function testSwapType7() public {
        vm.rollFork(17_000_000); //change block because this pool wasn't
            // deployed at block 16M
        uint256 amountIn = 10 ** 18;
        uint256 expAmountOut = 743676671921315909289;
        address receiver = bob;
        deal(WETH_ADDR, swapMethodAddress, amountIn);
        bytes memory data = abi.encodePacked(
            getDataCurve(LDO, LDO_POOL, receiver, 7, 0, 1, true), receiver
        );

        uint256 amountOut = swapMethod.swap(amountIn, data);

        uint256 finalBalance = LDO.balanceOf(bob);
        assertGe(finalBalance, expAmountOut);
        assertEq(amountOut, expAmountOut);
    }
    // Curve v2 2 token not factory pool

    function testSwapType8() public {
        vm.rollFork(17_000_000); //change block because this pool wasn't
            // deployed at block 16M
        uint256 amountIn = 10 ** 18;
        uint256 expAmountOut = 1831110768300490995125;
        address receiver = bob;
        deal(WETH_ADDR, swapMethodAddress, amountIn);
        bytes memory data = abi.encodePacked(
            getDataCurve(CRV, CRV_POOL, receiver, 8, 0, 1, true), receiver
        );

        uint256 amountOut = swapMethod.swap(amountIn, data);

        uint256 finalBalance = CRV.balanceOf(bob);
        assertGe(finalBalance, expAmountOut);
        assertEq(amountOut, expAmountOut);
    }

    function testDecodeParams() public {
        CurveSwapExecutorExposed swapMethodExposed =
            new CurveSwapExecutorExposed();

        //Logic
        bytes memory data = getDataCurve(LDO, LDO_POOL, bob, 7, 0, 1, true);
        (
            IERC20 tokenOut,
            address target,
            address receiver,
            uint8 poolType,
            int128 i,
            int128 j,
            bool tokenApprovalNeeded
        ) = swapMethodExposed.decodeParams(data);

        //Assertions
        assertEq(address(tokenOut), LDO_ADDR);
        assertEq(address(target), LDO_POOL);
        assertEq(address(receiver), bob);
        assertEq(poolType, 7);
        assertEq(i, 0);
        assertEq(j, 1);
        assertEq(tokenApprovalNeeded, true);
    }

    function getDataCurve(
        IERC20 tokenOut,
        address pool,
        address receiver,
        uint8 poolType,
        uint8 i,
        uint8 j,
        bool tokenApprovalNeeded
    ) internal pure returns (bytes memory data) {
        data = abi.encodePacked(
            tokenOut, pool, receiver, poolType, i, j, tokenApprovalNeeded
        );
    }
}
