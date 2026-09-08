pragma solidity ^0.8.26;

import "../TychoRouterTestSetup.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {
    IAccessControl
} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {MockPropAMM} from "./PropAMM.t.sol";
import {TransferManager} from "../../src/TransferManager.sol";
import {
    FallbackExecutor,
    FallbackExecutor__AddressZero,
    FallbackExecutor__InvalidDataLength
} from "../../src/executors/FallbackExecutor.sol";
import {
    TychoFallbackRouter,
    TychoFallbackRouter__AddressZero,
    TychoFallbackRouter__CallbackTokenMismatch,
    TychoFallbackRouter__InvalidSwapLength,
    TychoFallbackRouter__InvalidCallback,
    TychoFallbackRouter__NotPoolManager,
    TychoFallbackRouter__UnknownVenue,
    TychoFallbackRouter__NotSelf,
    TychoFallbackRouter__ZeroGasCap
} from "../../src/fallback/TychoFallbackRouter.sol";

/// @notice Builds the venue entries `TychoFallbackRouter` decodes.
library FallbackSwaps {
    function leg(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        address receiver
    ) internal pure returns (TychoFallbackRouter.Leg memory) {
        return TychoFallbackRouter.Leg({
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            amountIn: amountIn,
            receiver: receiver
        });
    }

    function uniswapV2(address pair, uint8 feeBps)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            uint8(TychoFallbackRouter.Venue.UniswapV2), pair, feeBps
        );
    }

    function uniswapV3(address pool) internal pure returns (bytes memory) {
        return
            abi.encodePacked(uint8(TychoFallbackRouter.Venue.UniswapV3), pool);
    }

    function uniswapV4(
        uint24 fee,
        int24 tickSpacing,
        address hook,
        bytes memory hookData
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            uint8(TychoFallbackRouter.Venue.UniswapV4),
            bytes3(fee),
            tickSpacing,
            hook,
            hookData
        );
    }

    function curve(address pool, uint8 poolType, uint8 i, uint8 j)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            uint8(TychoFallbackRouter.Venue.Curve), pool, poolType, i, j
        );
    }

    function fluidV1(address dex, bool zero2one)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            uint8(TychoFallbackRouter.Venue.FluidV1), dex, zero2one
        );
    }
}

/// @notice Accepts `tokenIn` and reports success without paying anything.
contract SilentVenue {
    function swap(
        address, /* tokenIn */
        address, /* tokenOut */
        uint256, /* amountIn */
        uint256, /* minAmountOut */
        address, /* recipient */
        uint256 /* deadline */
    )
        external
        pure
        returns (uint256 amountOut)
    {
        return 0;
    }
}

/// @notice Fails by consuming all forwarded gas -- the failure mode the pAMM gas cap exists for.
contract GasBurnerPropAMM {
    function swap(
        address, /* tokenIn */
        address, /* tokenOut */
        uint256, /* amountIn */
        uint256, /* minAmountOut */
        address, /* recipient */
        uint256 /* deadline */
    )
        external
        pure
        returns (uint256 amountOut)
    {
        // slither-disable-next-line assembly
        assembly {
            for {} 1 {} {}
        }
    }
}

/// @notice The claim the contract exists for: a reverting pAMM still delivers `tokenOut`, through
/// a venue an executor could never reach.
contract TychoFallbackRouterTest is Constants, TestUtils {
    using FallbackSwaps for bytes;

    TychoFallbackRouter router;
    MockPropAMM pamm;

    uint256 constant USDC_IN = 10_000e6;

    function setUp() public {
        vm.createSelectFork(vm.rpcUrl("mainnet"), 22689128);
        router = new TychoFallbackRouter(
            ADMIN, IPoolManager(POOL_MANAGER), FLUIDV1_LIQUIDITY
        );
        bytes32 callerRole = router.CALLER_ROLE();
        vm.prank(ADMIN);
        router.grantRole(callerRole, address(this));
        pamm = new MockPropAMM();
    }

    /// Only `CALLER_ROLE` (the TychoRouter) may start a swap; held balances
    /// are not first-come-first-served.
    function testSwapRequiresCallerRole() public {
        deal(USDC_ADDR, address(router), USDC_IN);
        bytes32 callerRole = router.CALLER_ROLE();

        vm.prank(BOB);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                BOB,
                callerRole
            )
        );
        router.swap(
            FallbackSwaps.leg(USDC_ADDR, USDC_ADDR, USDC_IN, BOB),
            BOB,
            FallbackSwaps.uniswapV3(USDC_WETH_USV3)
        );
    }

    /// The enum ordinals are the wire format the encoder emits (the venue
    /// table in CLAUDE.md); reordering the enum must fail here, not silently.
    function testVenueWireFormatIsStable() public pure {
        assertEq(uint8(TychoFallbackRouter.Venue.UniswapV2), 0);
        assertEq(uint8(TychoFallbackRouter.Venue.UniswapV3), 1);
        assertEq(uint8(TychoFallbackRouter.Venue.UniswapV4), 2);
        assertEq(uint8(TychoFallbackRouter.Venue.Curve), 3);
        assertEq(uint8(TychoFallbackRouter.Venue.FluidV1), 4);
    }

    function testConstructorRejectsZeroAddress() public {
        vm.expectRevert(TychoFallbackRouter__AddressZero.selector);
        new TychoFallbackRouter(
            address(0), IPoolManager(POOL_MANAGER), FLUIDV1_LIQUIDITY
        );

        vm.expectRevert(TychoFallbackRouter__AddressZero.selector);
        new TychoFallbackRouter(
            ADMIN, IPoolManager(address(0)), FLUIDV1_LIQUIDITY
        );

        vm.expectRevert(TychoFallbackRouter__AddressZero.selector);
        new TychoFallbackRouter(ADMIN, IPoolManager(POOL_MANAGER), address(0));
    }

    /// A live pAMM fills and the fallback is never touched.
    function testPropAMMFillsPrimary() public {
        // 1 WETH for the whole 10 000 USDC, far off the Uniswap V3 price of roughly 4 WETH, so
        // the asserted amount can only have come from the pAMM.
        pamm.setPrice(USDC_ADDR, WETH_ADDR, 1e26);
        deal(WETH_ADDR, address(pamm), 100 ether);
        deal(USDC_ADDR, address(router), USDC_IN);

        router.swap(
            FallbackSwaps.leg(USDC_ADDR, WETH_ADDR, USDC_IN, BOB),
            address(pamm),
            FallbackSwaps.uniswapV3(USDC_WETH_USV3)
        );

        assertEq(IERC20(WETH_ADDR).balanceOf(BOB), 1 ether);
        assertEq(IERC20(USDC_ADDR).balanceOf(address(pamm)), USDC_IN);
        _assertRouterDrained(USDC_ADDR, WETH_ADDR);
    }

    /// The pAMM has no price, so `quote` reverts. Uniswap V3 pays inside its callback, reachable
    /// only because this contract still holds the USDC.
    function testFallsBackToUniswapV3() public {
        deal(USDC_ADDR, address(router), USDC_IN);

        router.swap(
            FallbackSwaps.leg(USDC_ADDR, WETH_ADDR, USDC_IN, BOB),
            address(pamm),
            FallbackSwaps.uniswapV3(USDC_WETH_USV3)
        );

        assertGt(IERC20(WETH_ADDR).balanceOf(BOB), 0);
        // The failed primary's transfer reverted with it.
        assertEq(IERC20(USDC_ADDR).balanceOf(address(pamm)), 0);
        _assertRouterDrained(USDC_ADDR, WETH_ADDR);
    }

    /// The fallback starts from the full `amountIn`, whatever the primarySwap consumed.
    function testFallsBackToUniswapV2() public {
        deal(USDC_ADDR, address(router), USDC_IN);

        router.swap(
            FallbackSwaps.leg(USDC_ADDR, WETH_ADDR, USDC_IN, BOB),
            address(pamm),
            FallbackSwaps.uniswapV2(USDC_WETH_USV2, 30)
        );

        assertGt(IERC20(WETH_ADDR).balanceOf(BOB), 0);
        _assertRouterDrained(USDC_ADDR, WETH_ADDR);
    }

    /// Curve pays the caller, so the swap forwards the output itself.
    function testFallsBackToCurve() public {
        uint256 amountIn = 1000e18;
        deal(DAI_ADDR, address(router), amountIn);

        router.swap(
            FallbackSwaps.leg(DAI_ADDR, USDC_ADDR, amountIn, BOB),
            address(pamm),
            FallbackSwaps.curve(TRIPOOL, 1, 0, 1)
        );

        assertGt(IERC20(USDC_ADDR).balanceOf(BOB), 0);
        _assertRouterDrained(DAI_ADDR, USDC_ADDR);
        assertEq(IERC20(DAI_ADDR).allowance(address(router), TRIPOOL), 0);
    }

    /// V4 runs inside `unlockCallback`, where this contract syncs, transfers and settles.
    function testFallsBackToUniswapV4() public {
        uint256 amountIn = 100 ether;
        deal(USDE_ADDR, address(router), amountIn);

        router.swap(
            FallbackSwaps.leg(USDE_ADDR, USDT_ADDR, amountIn, BOB),
            address(pamm),
            FallbackSwaps.uniswapV4(100, 1, address(0), bytes(""))
        );

        assertGt(IERC20(USDT_ADDR).balanceOf(BOB), 0);
        _assertRouterDrained(USDE_ADDR, USDT_ADDR);
    }

    /// Zero output counts as a failure and takes back the `tokenIn` already sent.
    function testVenuePayingNothingFallsThrough() public {
        SilentVenue silent = new SilentVenue();
        deal(USDC_ADDR, address(router), USDC_IN);

        router.swap(
            FallbackSwaps.leg(USDC_ADDR, WETH_ADDR, USDC_IN, BOB),
            address(silent),
            FallbackSwaps.uniswapV3(USDC_WETH_USV3)
        );

        assertGt(IERC20(WETH_ADDR).balanceOf(BOB), 0);
        assertEq(IERC20(USDC_ADDR).balanceOf(address(silent)), 0);
        _assertRouterDrained(USDC_ADDR, WETH_ADDR);
    }

    /// A pAMM that fails by consuming gas burns only the cap. With a realistic
    /// 2M budget an uncapped try would leave the fallback ~1/64 and starve it.
    function testGasBurningPropAMMFallsBack() public {
        GasBurnerPropAMM burner = new GasBurnerPropAMM();
        deal(USDC_ADDR, address(router), USDC_IN);

        router.swap{gas: 2_000_000}(
            FallbackSwaps.leg(USDC_ADDR, WETH_ADDR, USDC_IN, BOB),
            address(burner),
            FallbackSwaps.uniswapV3(USDC_WETH_USV3)
        );

        assertGt(IERC20(WETH_ADDR).balanceOf(BOB), 0);
        _assertRouterDrained(USDC_ADDR, WETH_ADDR);
    }

    function testSetPammGasCap() public {
        assertEq(router.pammGasCap(), 1_000_000);

        vm.prank(BOB);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                BOB,
                bytes32(0)
            )
        );
        router.setPammGasCap(2_000_000);

        vm.prank(ADMIN);
        vm.expectRevert(TychoFallbackRouter__ZeroGasCap.selector);
        router.setPammGasCap(0);

        vm.prank(ADMIN);
        router.setPammGasCap(2_000_000);
        assertEq(router.pammGasCap(), 2_000_000);
    }

    /// A failing fallback reverts the swap. There is no third attempt.
    function testFallbackFailureReverts() public {
        deal(USDC_ADDR, address(router), USDC_IN);

        vm.expectRevert();
        router.swap(
            FallbackSwaps.leg(USDC_ADDR, WETH_ADDR, USDC_IN, BOB),
            address(pamm),
            FallbackSwaps.uniswapV3(makeAddr("not a pool"))
        );
    }

    function testUnknownFallbackVenueReverts() public {
        deal(USDC_ADDR, address(router), USDC_IN);

        vm.expectRevert(
            abi.encodeWithSelector(
                TychoFallbackRouter__UnknownVenue.selector, uint8(9)
            )
        );
        router.swap(
            FallbackSwaps.leg(USDC_ADDR, WETH_ADDR, USDC_IN, BOB),
            address(pamm),
            abi.encodePacked(uint8(9), USDC_WETH_USV3)
        );
    }

    function testEmptyFallbackReverts() public {
        deal(USDC_ADDR, address(router), USDC_IN);

        vm.expectRevert(
            abi.encodeWithSelector(
                TychoFallbackRouter__InvalidSwapLength.selector, uint256(0)
            )
        );
        router.swap(
            FallbackSwaps.leg(USDC_ADDR, WETH_ADDR, USDC_IN, BOB),
            address(pamm),
            bytes("")
        );
    }

    /// `executePropAMM` is external only so `swap` can wrap it in try/catch.
    function testExecutePropAMMRejectsExternalCaller() public {
        vm.expectRevert(TychoFallbackRouter__NotSelf.selector);
        router.executePropAMM(
            FallbackSwaps.leg(USDC_ADDR, WETH_ADDR, USDC_IN, BOB), address(pamm)
        );
    }

    /// No swap is running, so there is no venue that may be paid.
    function testUniswapV3CallbackRejectsStranger() public {
        vm.expectRevert(TychoFallbackRouter__InvalidCallback.selector);
        router.uniswapV3SwapCallback(1, -1, bytes(""));
    }

    function testDexCallbackRejectsStranger() public {
        vm.expectRevert(TychoFallbackRouter__InvalidCallback.selector);
        router.dexCallback(USDC_ADDR, USDC_IN);
    }

    function testUnlockCallbackRejectsStranger() public {
        vm.expectRevert(TychoFallbackRouter__NotPoolManager.selector);
        router.unlockCallback(bytes(""));
    }

    function testRescueRequiresAdmin() public {
        deal(USDC_ADDR, address(router), 1e6);

        vm.prank(BOB);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                BOB,
                bytes32(0)
            )
        );
        router.rescue(USDC_ADDR, BOB, 1e6);

        vm.prank(ADMIN);
        router.rescue(USDC_ADDR, BOB, 1e6);
        assertEq(IERC20(USDC_ADDR).balanceOf(BOB), 1e6);
    }

    /// Holds no funds once a leg is done.
    function _assertRouterDrained(address tokenIn, address tokenOut)
        internal
        view
    {
        assertEq(IERC20(tokenIn).balanceOf(address(router)), 0);
        assertEq(IERC20(tokenOut).balanceOf(address(router)), 0);
    }
}

/// @notice Fluid pulls `tokenIn` through `dexCallback`. Forked where the dex is live.
contract TychoFallbackRouterFluidTest is Constants, TestUtils {
    address constant FLUID_DEX = 0x1DD125C32e4B5086c63CC13B3cA02C4A2a61Fa9b;
    address constant SUSDE_ADDR = 0x9D39A5DE30e57443BfF2A8307A4256c8797A3497;

    TychoFallbackRouter router;
    MockPropAMM pamm;

    function setUp() public {
        vm.createSelectFork(vm.rpcUrl("mainnet"), 23748828);
        router = new TychoFallbackRouter(
            ADMIN, IPoolManager(POOL_MANAGER), FLUIDV1_LIQUIDITY
        );
        bytes32 callerRole = router.CALLER_ROLE();
        vm.prank(ADMIN);
        router.grantRole(callerRole, address(this));
        pamm = new MockPropAMM();
    }

    function testFallsBackToFluidV1() public {
        uint256 amountIn = 10e18;
        deal(SUSDE_ADDR, address(router), amountIn);

        router.swap(
            FallbackSwaps.leg(SUSDE_ADDR, USDT_ADDR, amountIn, BOB),
            address(pamm),
            FallbackSwaps.fluidV1(FLUID_DEX, true)
        );

        assertGt(IERC20(USDT_ADDR).balanceOf(BOB), 0);
        assertEq(IERC20(SUSDE_ADDR).balanceOf(address(router)), 0);
    }

    /// A mis-encoded `zero2one` makes the dex request the other side; the
    /// failure names the cause instead of dying inside Fluid's accounting.
    function testFluidWrongDirectionNamesCause() public {
        uint256 amountIn = 10e18;
        deal(SUSDE_ADDR, address(router), amountIn);

        vm.expectRevert(
            abi.encodeWithSelector(
                TychoFallbackRouter__CallbackTokenMismatch.selector,
                USDT_ADDR,
                SUSDE_ADDR
            )
        );
        router.swap(
            FallbackSwaps.leg(SUSDE_ADDR, USDT_ADDR, amountIn, BOB),
            address(pamm),
            FallbackSwaps.fluidV1(FLUID_DEX, false)
        );
    }
}

/// @notice The same claim through the whole TychoRouter: the leg's input lands at the fallback
/// router, not at a pool, which is what makes the retry fundable.
contract FallbackExecutorTest is TychoRouterTestSetup {
    MockPropAMM pamm;

    function getForkBlock() public pure override returns (uint256) {
        return 22689128;
    }

    function setUp() public override {
        super.setUp();
        pamm = new MockPropAMM();
    }

    function testGetTransferData() public view {
        (
            TransferManager.TransferType transferType,
            address receiver,
            address tokenIn,
            address tokenOut,
            bool outputToRouter
        ) = fallbackExecutor.getTransferData(_swapData());

        assertEq(
            uint8(transferType), uint8(TransferManager.TransferType.Transfer)
        );
        assertEq(receiver, address(fallbackRouter));
        assertEq(tokenIn, USDC_ADDR);
        assertEq(tokenOut, WETH_ADDR);
        assertFalse(outputToRouter);
    }

    function testFundsExpectedAddress() public view {
        assertEq(
            fallbackExecutor.fundsExpectedAddress(_swapData()),
            address(fallbackRouter)
        );
    }

    function testInvalidDataLength() public {
        vm.expectRevert(FallbackExecutor__InvalidDataLength.selector);
        fallbackExecutor.getTransferData(abi.encodePacked(USDC_ADDR, WETH_ADDR));
    }

    function testConstructorRejectsZeroAddress() public {
        vm.expectRevert(FallbackExecutor__AddressZero.selector);
        new FallbackExecutor(address(0));
    }

    /// The whole leg: a dead pAMM still settles, at the Uniswap V3 price.
    function testSingleSwap() public {
        uint256 amountIn = 10_000e6;
        deal(USDC_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(tychoRouterAddr, amountIn);
        uint256 amountOut = tychoRouter.singleSwap(
            amountIn,
            USDC_ADDR,
            WETH_ADDR,
            1 ether,
            1 ether,
            ALICE,
            noClientFee(),
            encodeSingleSwap(address(fallbackExecutor), _swapData())
        );
        vm.stopPrank();

        assertGt(amountOut, 1 ether);
        assertEq(IERC20(WETH_ADDR).balanceOf(ALICE), amountOut);
        assertEq(IERC20(USDC_ADDR).balanceOf(tychoRouterAddr), 0);
        assertEq(IERC20(USDC_ADDR).balanceOf(address(fallbackRouter)), 0);
    }

    /// The TychoRouter's `minAmountOut` is the leg's only price check.
    function testSingleSwapMinAmountOutBinds() public {
        uint256 amountIn = 10_000e6;
        deal(USDC_ADDR, ALICE, amountIn);

        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(tychoRouterAddr, amountIn);
        vm.expectRevert();
        tychoRouter.singleSwap(
            amountIn,
            USDC_ADDR,
            WETH_ADDR,
            1000 ether,
            1000 ether,
            ALICE,
            noClientFee(),
            encodeSingleSwap(address(fallbackExecutor), _swapData())
        );
        vm.stopPrank();
    }

    /// The fallback leg funds the next hop's pool directly.
    function testSequentialSwap() public {
        uint256 amountIn = 10_000e6;
        deal(USDC_ADDR, ALICE, amountIn);

        bytes[] memory swaps = new bytes[](2);
        swaps[0] = encodeSequentialSwap(address(fallbackExecutor), _swapData());
        swaps[1] = encodeSequentialSwap(
            address(usv2Executor),
            encodeUniswapV2Swap(DAI_WETH_UNIV2_POOL, WETH_ADDR, DAI_ADDR)
        );

        vm.startPrank(ALICE);
        IERC20(USDC_ADDR).approve(tychoRouterAddr, amountIn);
        uint256 amountOut = tychoRouter.sequentialSwap(
            amountIn,
            USDC_ADDR,
            DAI_ADDR,
            1000e18,
            1000e18,
            ALICE,
            noClientFee(),
            pleEncode(swaps)
        );
        vm.stopPrank();

        assertGt(amountOut, 1000e18);
        assertEq(IERC20(DAI_ADDR).balanceOf(ALICE), amountOut);
        assertEq(IERC20(WETH_ADDR).balanceOf(address(fallbackRouter)), 0);
    }

    /// A pAMM with no price, then a Uniswap V3 retry. Executor swap data is
    /// `[tokenIn: 20][tokenOut: 20][pamm: 20][fallback]`.
    function _swapData() internal view returns (bytes memory) {
        return abi.encodePacked(
            USDC_ADDR,
            WETH_ADDR,
            address(pamm),
            FallbackSwaps.uniswapV3(USDC_WETH_USV3)
        );
    }
}
