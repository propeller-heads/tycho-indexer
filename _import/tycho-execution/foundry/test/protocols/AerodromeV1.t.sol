pragma solidity ^0.8.26;

import {Test} from "../../lib/forge-std/src/Test.sol";
import {
    AerodromeV1Executor,
    AerodromeV1Executor__InvalidDataLength,
    AerodromeV1Executor__InvalidTokenPair,
    IAerodromeV1Pool
} from "@src/executors/AerodromeV1Executor.sol";
import {TransferManager} from "@src/TransferManager.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor(string memory name_, string memory symbol_)
        ERC20(name_, symbol_)
    {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract MockAerodromeV1Pool is IAerodromeV1Pool {
    address public immutable override token0;
    address public immutable override token1;
    uint256 public immutable rate;

    constructor(address token0_, address token1_, uint256 rate_) {
        token0 = token0_;
        token1 = token1_;
        rate = rate_;
    }

    function getAmountOut(uint256 amountIn, address tokenIn)
        external
        view
        override
        returns (uint256)
    {
        require(tokenIn == token0 || tokenIn == token1, "invalid tokenIn");
        return (amountIn * rate) / 1e18;
    }

    function swap(
        uint256 amount0Out,
        uint256 amount1Out,
        address to,
        bytes calldata
    ) external override {
        if (amount0Out > 0) {
            ERC20(token0).transfer(to, amount0Out);
        }
        if (amount1Out > 0) {
            ERC20(token1).transfer(to, amount1Out);
        }
    }
}

contract AerodromeV1ExecutorExposed is AerodromeV1Executor {
    function decodeParams(bytes calldata data)
        external
        pure
        returns (address target, address tokenIn, address tokenOut)
    {
        return _decodeData(data);
    }
}

contract AerodromeV1ExecutorTest is Test {
    AerodromeV1ExecutorExposed executor;
    MockERC20 token0;
    MockERC20 token1;
    MockAerodromeV1Pool pool;

    function setUp() public {
        executor = new AerodromeV1ExecutorExposed();
        token0 = new MockERC20("token0", "TK0");
        token1 = new MockERC20("token1", "TK1");
        pool = new MockAerodromeV1Pool(address(token0), address(token1), 2e18);

        token0.mint(address(pool), 1_000_000e18);
        token1.mint(address(pool), 1_000_000e18);
    }

    function testDecodeParams() public view {
        bytes memory params =
            abi.encodePacked(address(pool), address(token0), address(token1));

        (address target, address tokenIn, address tokenOut) =
            executor.decodeParams(params);

        assertEq(target, address(pool));
        assertEq(tokenIn, address(token0));
        assertEq(tokenOut, address(token1));
    }

    function testDecodeParamsInvalidDataLength() public {
        bytes memory invalidParams = abi.encodePacked(address(pool), address(token0));

        vm.expectRevert(AerodromeV1Executor__InvalidDataLength.selector);
        executor.decodeParams(invalidParams);
    }

    function testGetTransferData() public {
        bytes memory params =
            abi.encodePacked(address(pool), address(token0), address(token1));

        (
            TransferManager.TransferType transferType,
            address receiver,
            address tokenIn,
            address tokenOut,
            bool outputToRouter
        ) = executor.getTransferData(params);

        assertEq(uint8(transferType), uint8(TransferManager.TransferType.Transfer));
        assertEq(receiver, address(pool));
        assertEq(tokenIn, address(token0));
        assertEq(tokenOut, address(token1));
        assertEq(outputToRouter, false);
    }

    function testFundsExpectedAddress() public view {
        bytes memory params =
            abi.encodePacked(address(pool), address(token0), address(token1));
        address receiver = executor.fundsExpectedAddress(params);
        assertEq(receiver, address(pool));
    }

    function testSwapZeroForOne() public {
        uint256 amountIn = 10e18;
        uint256 expectedAmountOut = 20e18;
        bytes memory protocolData =
            abi.encodePacked(address(pool), address(token0), address(token1));

        token0.mint(address(executor), amountIn);
        vm.prank(address(executor));
        token0.transfer(address(pool), amountIn);

        uint256 balanceBefore = token1.balanceOf(address(this));
        executor.swap(amountIn, protocolData, address(this));
        uint256 balanceAfter = token1.balanceOf(address(this));

        assertEq(balanceAfter - balanceBefore, expectedAmountOut);
        assertEq(token0.balanceOf(address(executor)), 0);
    }

    function testSwapOneForZero() public {
        uint256 amountIn = 3e18;
        uint256 expectedAmountOut = 6e18;
        bytes memory protocolData =
            abi.encodePacked(address(pool), address(token1), address(token0));

        token1.mint(address(executor), amountIn);
        vm.prank(address(executor));
        token1.transfer(address(pool), amountIn);

        uint256 balanceBefore = token0.balanceOf(address(this));
        executor.swap(amountIn, protocolData, address(this));
        uint256 balanceAfter = token0.balanceOf(address(this));

        assertEq(balanceAfter - balanceBefore, expectedAmountOut);
        assertEq(token1.balanceOf(address(executor)), 0);
    }

    function testSwapRevertOnInvalidPair() public {
        bytes memory protocolData =
            abi.encodePacked(address(pool), address(token0), address(0x1234));

        vm.expectRevert(AerodromeV1Executor__InvalidTokenPair.selector);
        executor.swap(1e18, protocolData, address(this));
    }
}
