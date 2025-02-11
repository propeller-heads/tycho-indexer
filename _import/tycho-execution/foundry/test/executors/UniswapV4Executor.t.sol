// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import "@src/executors/UniswapV4Executor.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";
import {Constants} from "../Constants.sol";
import {console} from "forge-std/console.sol";

contract UniswapV4ExecutorExposed is UniswapV4Executor {
    constructor(IPoolManager _poolManager) UniswapV4Executor(_poolManager) {}

    function decodeData(bytes calldata data)
        external
        pure
        returns (
            address tokenOut,
            address receiver,
            bool isExactInput,
            uint256 amount
        )
    {
        return _decodeData(data);
    }
}

contract UniswapV4ExecutorTest is Test, Constants {
    using SafeERC20 for IERC20;

    UniswapV4ExecutorExposed uniswapV4Exposed;
    IERC20 USDE = IERC20(USDE_ADDR);
    IERC20 USDT = IERC20(USDT_ADDR);
    address poolManager = 0x000000000004444c5dc75cB358380D2e3dE08A90;

    function setUp() public {
        uint256 forkBlock = 21817316;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        uniswapV4Exposed =
            new UniswapV4ExecutorExposed(IPoolManager(poolManager));
    }

    function testDecodeParamsUniswapV4() public view {
        uint24 expectedPoolFee = 500;
        address expectedReceiver = address(2);
        uint128 expectedAmount = 100;

        bytes memory data = _encodeExactInputSingle(
            USDE_ADDR,
            USDT_ADDR,
            expectedPoolFee,
            expectedReceiver,
            false,
            1,
            expectedAmount
        );

        (address tokenOut, address receiver, bool isExactInput, uint256 amount)
        = uniswapV4Exposed.decodeData(data);

        assertEq(tokenOut, USDT_ADDR);
        assertEq(receiver, expectedReceiver);
        assertTrue(isExactInput);
        assertEq(amount, expectedAmount);
    }

    function testSwapUniswapV4() public {
        vm.startPrank(BOB);
        uint256 amountIn = 100 ether;
        deal(USDE_ADDR, address(uniswapV4Exposed), amountIn);
        uint256 usdeBalanceBeforePool = USDE.balanceOf(poolManager);
        uint256 usdeBalanceBeforeSwapExecutor =
            USDE.balanceOf(address(uniswapV4Exposed));
        assertEq(usdeBalanceBeforeSwapExecutor, amountIn);
        uint256 usdtBalanceBeforeSwapBob = USDT.balanceOf(address(BOB));
        assertEq(usdtBalanceBeforeSwapBob, 0);

        bytes memory data = _encodeExactInputSingle(
            USDE_ADDR, USDT_ADDR, 100, BOB, true, 1, uint128(amountIn)
        );

        uint256 amountOut = uniswapV4Exposed.swap(amountIn, data);
        assertEq(USDE.balanceOf(poolManager), usdeBalanceBeforePool + amountIn);
        assertEq(
            USDE.balanceOf(address(uniswapV4Exposed)),
            usdeBalanceBeforeSwapExecutor - amountIn
        );
        assertTrue(USDT.balanceOf(BOB) == amountOut && amountOut > 0);
    }

    function _encodeExactInputSingle(
        address tokenIn,
        address tokenOut,
        uint24 fee,
        address receiver,
        bool zeroForOne,
        uint24 tickSpacing,
        uint128 amountIn
    ) internal pure returns (bytes memory) {
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(zeroForOne ? tokenIn : tokenOut),
            currency1: Currency.wrap(zeroForOne ? tokenOut : tokenIn),
            fee: fee,
            tickSpacing: int24(tickSpacing),
            hooks: IHooks(address(0))
        });

        bytes memory actions = abi.encodePacked(
            uint8(Actions.SWAP_EXACT_IN_SINGLE),
            uint8(Actions.SETTLE_ALL),
            uint8(Actions.TAKE)
        );

        bytes[] memory params = new bytes[](3);

        params[0] = abi.encode(
            IV4Router.ExactInputSingleParams({
                poolKey: key,
                zeroForOne: zeroForOne,
                amountIn: amountIn,
                amountOutMinimum: 0,
                hookData: bytes("")
            })
        );

        params[1] = abi.encode(key.currency0, amountIn);
        params[2] = abi.encode(key.currency1, receiver, 0);

        return abi.encode(actions, params);
    }
}
