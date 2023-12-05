// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import {
    BalancerV2SwapAdapter,
    IERC20,
    IVault
} from "src/balancer-v2/BalancerV2SwapAdapter.sol";
import {ISwapAdapterTypes} from "src/interfaces/ISwapAdapterTypes.sol";

contract BalancerV2SwapAdapterTest is Test, ISwapAdapterTypes {
    IVault constant balancerV2Vault =
        IVault(payable(0xBA12222222228d8Ba445958a75a0704d566BF2C8));
    BalancerV2SwapAdapter adapter;

    IERC20 constant WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IERC20 constant BAL = IERC20(0xba100000625a3754423978a60c9317c58a424e3D);
    address constant B_80BAL_20WETH = 0x5c6Ee304399DBdB9C8Ef030aB642B10820DB8F56;
    bytes32 constant B_80BAL_20WETH_POOL_ID =
        0x5c6ee304399dbdb9c8ef030ab642b10820db8f56000200000000000000000014;

    function setUp() public {
        uint256 forkBlock = 18710000;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);

        adapter = new BalancerV2SwapAdapter(payable(address(balancerV2Vault)));

        vm.label(address(balancerV2Vault), "IVault");
        vm.label(address(adapter), "BalancerV2SwapAdapter");
        vm.label(address(WETH), "WETH");
        vm.label(address(BAL), "BAL");
        vm.label(address(B_80BAL_20WETH), "B_80BAL_20WETH");
    }

    function testPrice() public {
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 100;
        amounts[1] = 200;
        vm.expectRevert(
            abi.encodeWithSelector(
                NotImplemented.selector, "BalancerV2SwapAdapter.price"
            )
        );
        adapter.price(B_80BAL_20WETH_POOL_ID, BAL, WETH, amounts);
    }

    // function testPriceSingleFuzz(uint256 amount) public {
    //     uint256[] memory limits = adapter.getLimits(B_80BAL_20WETH_POOL_ID, BAL, WETH);
    //     vm.assume(amount < limits[0]);
    //     vm.assume(amount > 100);

    //     uint256[] memory amounts = new uint256[](1);
    //     amounts[0] = amount;

    //     Fraction memory price =
    //         adapter.priceSingle(B_80BAL_20WETH_POOL_ID, BAL, WETH, amount);

    //     console.log("price.numerator: ", price.numerator);
    //     console.log("price.denominator: ", price.denominator);

    //     assertGt(price.numerator, 0);
    // }

    function testSwapFuzz(uint256 specifiedAmount, bool isBuy) public {
        OrderSide side = isBuy ? OrderSide.Buy : OrderSide.Sell;
        vm.assume(specifiedAmount > 0);

        uint256[] memory limits = adapter.getLimits(B_80BAL_20WETH_POOL_ID, BAL, WETH);

        if (side == OrderSide.Buy) {
            vm.assume(specifiedAmount < limits[1]);

            // sellAmount is not specified for buy orders
            deal(address(BAL), address(this), type(uint256).max);
            BAL.approve(address(adapter), type(uint256).max);
        }
        else {
            vm.assume(specifiedAmount < limits[0]);

            deal(address(BAL), address(this), specifiedAmount);
            BAL.approve(address(adapter), specifiedAmount);
        }
        
        uint256 bal_balance = BAL.balanceOf(address(this));
        uint256 weth_balance = WETH.balanceOf(address(this));

        Trade memory trade = adapter.swap(B_80BAL_20WETH_POOL_ID, BAL, WETH, side, specifiedAmount);

        if (trade.calculatedAmount > 0) {
            if (side == OrderSide.Buy) {
                assertEq(specifiedAmount, WETH.balanceOf(address(this)) - weth_balance);
                assertEq(trade.calculatedAmount, bal_balance - BAL.balanceOf(address(this)));
            } else {
                assertEq(specifiedAmount, bal_balance - BAL.balanceOf(address(this)));
                assertEq(trade.calculatedAmount, WETH.balanceOf(address(this)) - weth_balance);
            }
        }
    }

    function testGetLimits() public view {
        uint256[] memory limits =
            adapter.getLimits(B_80BAL_20WETH_POOL_ID, BAL, WETH);

        assert(limits.length == 2);
        assert(limits[0] > 0);
        assert(limits[1] > 0);
    }

    function testGetCapabilitiesFuzz(bytes32 pair, address t0, address t1) public {
        Capability[] memory res =
            adapter.getCapabilities(pair, IERC20(t0), IERC20(t1));

        assertEq(res.length, 2);
        assertEq(uint256(res[0]), uint256(Capability.SellOrder));
        assertEq(uint256(res[1]), uint256(Capability.BuyOrder));
    }

    function testGetTokens() public {
        IERC20[] memory tokens = adapter.getTokens(B_80BAL_20WETH_POOL_ID);

        assertEq(address(tokens[0]), address(BAL));
        assertEq(address(tokens[1]), address(WETH));
    }

    function testGetPoolIds() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                NotImplemented.selector, "BalancerV2SwapAdapter.getPoolIds"
            )
        );
        adapter.getPoolIds(100, 200);
    }
}
