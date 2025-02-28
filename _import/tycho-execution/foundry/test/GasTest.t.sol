// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

import {IUniversalRouter} from "../interfaces/IUniversalRouter.sol";
import {IPermit2} from "../lib/permit2/src/interfaces/IPermit2.sol";
import {Constants} from "./Constants.sol";
import {Actions} from "../lib/v4-periphery/src/libraries/Actions.sol";
import {PoolKey} from "../lib/v4-core/src/types/PoolKey.sol";
import {IV4Router} from "../lib/v4-periphery/src/interfaces/IV4Router.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Currency} from "../lib/v4-core/src/types/Currency.sol";
import {IHooks} from "../lib/v4-core/src/interfaces/IHooks.sol";
import "forge-std/Test.sol";

contract Commands {
    uint256 constant V2_SWAP_EXACT_IN = 0x08;
    uint256 constant V3_SWAP_EXACT_IN = 0x00;
    uint256 constant V4_SWAP = 0x10;
}

// A gas test to compare the gas usage of the UniversalRouter with the TychoRouter

contract GasTest is Commands, Test, Constants {
    IUniversalRouter universalRouter = IUniversalRouter(UNIVERSAL_ROUTER);
    IPermit2 permit2 = IPermit2(PERMIT2_ADDRESS);

    function setUp() public {
        uint256 forkBlock = 21817316;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
    }

    function testUniversalRouterUniswapV2() public {
        bool isPermit2 = false;
        uint256 amountIn = 10 ** 18;

        bytes memory commands =
            abi.encodePacked(uint8(Commands.V2_SWAP_EXACT_IN));

        address[] memory path = new address[](2);
        path[0] = WETH_ADDR;
        path[1] = DAI_ADDR;

        bytes[] memory inputs = new bytes[](1);
        inputs[0] = abi.encode(BOB, amountIn, uint256(0), path, isPermit2);

        deal(WETH_ADDR, address(universalRouter), amountIn);
        universalRouter.execute(commands, inputs, block.timestamp + 1000);
    }

    function testUniversalRouterUniswapV2Permit2() public {
        bool isPermit2 = true;
        uint256 amountIn = 10 ** 18;

        bytes memory commands =
            abi.encodePacked(uint8(Commands.V2_SWAP_EXACT_IN));

        address[] memory path = new address[](2);
        path[0] = WETH_ADDR;
        path[1] = DAI_ADDR;

        bytes[] memory inputs = new bytes[](1);
        inputs[0] = abi.encode(BOB, amountIn, uint256(0), path, isPermit2);

        deal(WETH_ADDR, address(this), amountIn);
        IERC20(WETH_ADDR).approve(PERMIT2_ADDRESS, amountIn);
        permit2.approve(
            WETH_ADDR,
            address(universalRouter),
            uint160(amountIn),
            uint48(block.timestamp + 1000)
        );
        universalRouter.execute(commands, inputs, block.timestamp + 1000);
    }

    function testUniversalRouterUniswapV3() public {
        bool isPermit2 = false;
        uint256 amountIn = 10 ** 18;

        bytes memory commands =
            abi.encodePacked(uint8(Commands.V3_SWAP_EXACT_IN));

        uint24 poolFee = 3000;
        bytes memory path = abi.encodePacked(WETH_ADDR, poolFee, DAI_ADDR);

        bytes[] memory inputs = new bytes[](1);
        inputs[0] = abi.encode(BOB, amountIn, uint256(0), path, isPermit2);

        deal(WETH_ADDR, address(universalRouter), amountIn);
        universalRouter.execute(commands, inputs, block.timestamp + 1000);
    }

    function testUniversalRouterUniswapV3Permit2() public {
        bool isPermit2 = true;
        uint256 amountIn = 10 ** 18;

        bytes memory commands =
            abi.encodePacked(uint8(Commands.V3_SWAP_EXACT_IN));

        uint24 poolFee = 3000;
        bytes memory path = abi.encodePacked(WETH_ADDR, poolFee, DAI_ADDR);

        bytes[] memory inputs = new bytes[](1);
        inputs[0] = abi.encode(BOB, amountIn, uint256(0), path, isPermit2);

        deal(WETH_ADDR, address(this), amountIn);
        IERC20(WETH_ADDR).approve(PERMIT2_ADDRESS, amountIn);
        permit2.approve(
            WETH_ADDR,
            address(universalRouter),
            uint160(amountIn),
            uint48(block.timestamp + 1000)
        );
        universalRouter.execute(commands, inputs, block.timestamp + 1000);
    }

    function testUniversalRouterUniswapV4Permit2() public {
        uint128 amountIn = uint128(100 ether);
        uint128 amountOutMinimum = uint128(0);
        uint256 deadline = block.timestamp + 1000;

        bytes memory commands = abi.encodePacked(uint8(Commands.V4_SWAP));

        bytes memory actions = abi.encodePacked(
            uint8(Actions.SWAP_EXACT_IN_SINGLE),
            uint8(Actions.SETTLE_ALL),
            uint8(Actions.TAKE_ALL)
        );

        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(USDE_ADDR),
            currency1: Currency.wrap(USDT_ADDR),
            fee: 100,
            tickSpacing: int24(1),
            hooks: IHooks(address(0))
        });

        bytes[] memory params = new bytes[](3);
        params[0] = abi.encode(
            IV4Router.ExactInputSingleParams({
                poolKey: key,
                zeroForOne: true,
                amountIn: amountIn,
                amountOutMinimum: amountOutMinimum,
                hookData: bytes("")
            })
        );

        params[1] = abi.encode(key.currency0, amountIn);
        params[2] = abi.encode(key.currency1, amountOutMinimum);

        bytes[] memory inputs = new bytes[](1);
        inputs[0] = abi.encode(actions, params);

        deal(USDE_ADDR, address(this), amountIn);
        IERC20(USDE_ADDR).approve(PERMIT2_ADDRESS, amountIn);
        permit2.approve(
            USDE_ADDR, address(universalRouter), amountIn, uint48(deadline)
        );
        universalRouter.execute(commands, inputs, deadline);
    }
}
