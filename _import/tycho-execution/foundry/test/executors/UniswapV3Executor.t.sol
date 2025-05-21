// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/executors/UniswapV3Executor.sol";
import "@permit2/src/interfaces/IAllowanceTransfer.sol";
import {Test} from "../../lib/forge-std/src/Test.sol";
import {Constants} from "../Constants.sol";
import {Permit2TestHelper} from "../Permit2TestHelper.sol";

contract UniswapV3ExecutorExposed is UniswapV3Executor {
    constructor(address _factory, bytes32 _initCode, address _permit2)
        UniswapV3Executor(_factory, _initCode, _permit2)
    {}

    function decodeData(bytes calldata data)
        external
        pure
        returns (
            address inToken,
            address outToken,
            uint24 fee,
            address receiver,
            address target,
            bool zeroForOne,
            RestrictTransferFrom.TransferType transferType
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
}

contract UniswapV3ExecutorTest is Test, Constants, Permit2TestHelper {
    using SafeERC20 for IERC20;

    UniswapV3ExecutorExposed uniswapV3Exposed;
    UniswapV3ExecutorExposed pancakeV3Exposed;
    IERC20 WETH = IERC20(WETH_ADDR);
    IERC20 DAI = IERC20(DAI_ADDR);
    IAllowanceTransfer permit2;

    function setUp() public {
        uint256 forkBlock = 17323404;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);

        uniswapV3Exposed = new UniswapV3ExecutorExposed(
            USV3_FACTORY_ETHEREUM, USV3_POOL_CODE_INIT_HASH, PERMIT2_ADDRESS
        );
        pancakeV3Exposed = new UniswapV3ExecutorExposed(
            PANCAKESWAPV3_DEPLOYER_ETHEREUM,
            PANCAKEV3_POOL_CODE_INIT_HASH,
            PERMIT2_ADDRESS
        );
        permit2 = IAllowanceTransfer(PERMIT2_ADDRESS);
    }

    function testDecodeParams() public view {
        uint24 expectedPoolFee = 500;
        bytes memory data = abi.encodePacked(
            WETH_ADDR,
            DAI_ADDR,
            expectedPoolFee,
            address(2),
            address(3),
            false,
            RestrictTransferFrom.TransferType.Transfer
        );

        (
            address tokenIn,
            address tokenOut,
            uint24 fee,
            address receiver,
            address target,
            bool zeroForOne,
            RestrictTransferFrom.TransferType transferType
        ) = uniswapV3Exposed.decodeData(data);

        assertEq(tokenIn, WETH_ADDR);
        assertEq(tokenOut, DAI_ADDR);
        assertEq(fee, expectedPoolFee);
        assertEq(receiver, address(2));
        assertEq(target, address(3));
        assertEq(zeroForOne, false);
        assertEq(
            uint8(transferType),
            uint8(RestrictTransferFrom.TransferType.Transfer)
        );
    }

    function testSwapIntegration() public {
        uint256 amountIn = 10 ** 18;
        deal(WETH_ADDR, address(uniswapV3Exposed), amountIn);

        uint256 expAmountOut = 1205_128428842122129186; //Swap 1 WETH for 1205.12 DAI
        bool zeroForOne = false;

        bytes memory data = encodeUniswapV3Swap(
            WETH_ADDR,
            DAI_ADDR,
            address(this),
            DAI_WETH_USV3,
            zeroForOne,
            RestrictTransferFrom.TransferType.Transfer
        );

        uint256 amountOut = uniswapV3Exposed.swap(amountIn, data);

        assertGe(amountOut, expAmountOut);
        assertEq(IERC20(WETH_ADDR).balanceOf(address(uniswapV3Exposed)), 0);
        assertGe(IERC20(DAI_ADDR).balanceOf(address(this)), expAmountOut);
    }

    function testDecodeParamsInvalidDataLength() public {
        bytes memory invalidParams =
            abi.encodePacked(WETH_ADDR, address(2), address(3));

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

        vm.startPrank(DAI_WETH_USV3);
        bytes memory protocolData = abi.encodePacked(
            WETH_ADDR,
            DAI_ADDR,
            poolFee,
            RestrictTransferFrom.TransferType.Transfer,
            address(uniswapV3Exposed)
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
            WETH_ADDR,
            DAI_ADDR,
            uint24(3000),
            address(this),
            fakePool,
            zeroForOne,
            RestrictTransferFrom.TransferType.Transfer
        );

        vm.expectRevert(UniswapV3Executor__InvalidTarget.selector);
        uniswapV3Exposed.swap(amountIn, protocolData);
    }

    function encodeUniswapV3Swap(
        address tokenIn,
        address tokenOut,
        address receiver,
        address target,
        bool zero2one,
        RestrictTransferFrom.TransferType transferType
    ) internal view returns (bytes memory) {
        IUniswapV3Pool pool = IUniswapV3Pool(target);
        return abi.encodePacked(
            tokenIn,
            tokenOut,
            pool.fee(),
            receiver,
            target,
            zero2one,
            transferType
        );
    }
}
