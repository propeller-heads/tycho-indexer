// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@src/FeeTaker.sol";
import "./Constants.sol";

contract FeeTakerExposed is FeeTaker {
    function decodeFeeData(bytes calldata data)
        external
        pure
        returns (
            uint16 solverFeeBps,
            address solverFeeReceiver,
            uint16 routerFeeOnOutputBps,
            uint16 routerFeeOnSolverFeeBps,
            address routerFeeReceiver,
            address token
        )
    {
        return _decodeFeeData(data);
    }
}

contract FeeTakerTest is Constants {
    FeeTakerExposed feeTakerExposed;

    function setUp() public {
        feeTakerExposed = new FeeTakerExposed();
    }

    function testDecodeFeeDataValid() public view {
        uint16 expectedSolverFeeBps = 100; // 1%
        address expectedSolverFeeReceiver = ALICE;
        uint16 expectedRouterFeeOnOutputBps = 50; // 0.5%
        uint16 expectedRouterFeeOnSolverFeeBps = 25; // 0.25%
        address expectedRouterFeeReceiver = BOB;
        address expectedToken = WETH_ADDR;
        bytes memory data = abi.encodePacked(
            expectedSolverFeeBps, // 2 bytes
            expectedSolverFeeReceiver, // 20 bytes
            expectedRouterFeeOnOutputBps, // 2 bytes
            expectedRouterFeeOnSolverFeeBps, // 2 bytes
            expectedRouterFeeReceiver, // 20 bytes
            expectedToken // 20 bytes
        );
        (
            uint16 solverFeeBps,
            address solverFeeReceiver,
            uint16 routerFeeOnOutputBps,
            uint16 routerFeeOnSolverFeeBps,
            address routerFeeReceiver,
            address token
        ) = feeTakerExposed.decodeFeeData(data);

        assertEq(solverFeeBps, expectedSolverFeeBps);
        assertEq(solverFeeReceiver, expectedSolverFeeReceiver);
        assertEq(routerFeeOnOutputBps, expectedRouterFeeOnOutputBps);
        assertEq(routerFeeOnSolverFeeBps, expectedRouterFeeOnSolverFeeBps);
        assertEq(routerFeeReceiver, expectedRouterFeeReceiver);
        assertEq(token, expectedToken);
    }

    function testDecodeFeeDataInvalidLength() public {
        // Test with data that's too short (65 bytes instead of 66)
        bytes memory data = new bytes(65);
        vm.expectRevert(
            abi.encodeWithSelector(FeeTaker__InvalidDataLength.selector)
        );
        feeTakerExposed.decodeFeeData(data);
    }

    function testTakeFeeOnlyRouterFeeOnOutput() public {
        // Test with only router fee on output set
        uint256 amountIn = 1 ether;
        uint16 solverFeeBps = 0;
        address solverFeeReceiver = address(0);
        uint16 routerFeeOnOutputBps = 100; // 1%
        uint16 routerFeeOnSolverFeeBps = 0;
        address routerFeeReceiver = BOB;
        address token = WETH_ADDR;

        bytes memory data = abi.encodePacked(
            solverFeeBps,
            solverFeeReceiver,
            routerFeeOnOutputBps,
            routerFeeOnSolverFeeBps,
            routerFeeReceiver,
            token
        );

        uint256 amountOut = feeTakerExposed.takeFee(amountIn, data);

        // routerFeeOnOutput = 1 ether * 100 / 10000 = 0.01 ether
        // amountOut = 1 ether - 0.01 ether = 0.99 ether
        uint256 expectedAmountOut =
            amountIn - (amountIn * routerFeeOnOutputBps / 10000);
        assertEq(amountOut, expectedAmountOut);
        assertEq(amountOut, 0.99 ether);

        // TODO: Check vault accounting when implemented
        // - routerFeeReceiver should have 0.01 ether credited
    }

    function testTakeFeeOnlyRouterFeeOnSolverFee() public {
        // Test with only router fee on solver fee set (requires solver fee to be set too)
        uint256 amountIn = 1 ether;
        uint16 solverFeeBps = 200; // 2%
        address solverFeeReceiver = ALICE;
        uint16 routerFeeOnOutputBps = 0;
        uint16 routerFeeOnSolverFeeBps = 1000; // 10% of solver fee
        address routerFeeReceiver = BOB;
        address token = WETH_ADDR;

        bytes memory data = abi.encodePacked(
            solverFeeBps,
            solverFeeReceiver,
            routerFeeOnOutputBps,
            routerFeeOnSolverFeeBps,
            routerFeeReceiver,
            token
        );

        uint256 amountOut = feeTakerExposed.takeFee(amountIn, data);

        // solverFee = 1 ether * 200 / 10000 = 0.02 ether
        // amountAfterSolverFee = 1 ether - 0.02 ether = 0.98 ether
        // routerFeeOnSolverFee = 0.02 ether * 1000 / 10000 = 0.002 ether
        // amountOut = 0.98 ether - 0.002 ether = 0.978 ether
        uint256 solverFee = amountIn * solverFeeBps / 10000;
        uint256 routerFeeOnSolverFee =
            solverFee * routerFeeOnSolverFeeBps / 10000;
        uint256 expectedAmountOut = amountIn - solverFee - routerFeeOnSolverFee;
        assertEq(amountOut, expectedAmountOut);
        assertEq(amountOut, 0.978 ether);

        // TODO: Check vault accounting when implemented
        // - solverFeeReceiver should have 0.02 ether credited
        // - routerFeeReceiver should have 0.002 ether credited
    }

    function testTakeFeeOnlySolverFee() public {
        // Test with only solver fee set, no router fees
        uint256 amountIn = 1 ether;
        uint16 solverFeeBps = 150; // 1.5%
        address solverFeeReceiver = ALICE;
        uint16 routerFeeOnOutputBps = 0;
        uint16 routerFeeOnSolverFeeBps = 0;
        address routerFeeReceiver = address(0);
        address token = WETH_ADDR;

        bytes memory data = abi.encodePacked(
            solverFeeBps,
            solverFeeReceiver,
            routerFeeOnOutputBps,
            routerFeeOnSolverFeeBps,
            routerFeeReceiver,
            token
        );

        uint256 amountOut = feeTakerExposed.takeFee(amountIn, data);

        // solverFee = 1 ether * 150 / 10000 = 0.015 ether
        // amountOut = 1 ether - 0.015 ether = 0.985 ether
        uint256 expectedAmountOut = amountIn - (amountIn * solverFeeBps / 10000);
        assertEq(amountOut, expectedAmountOut);
        assertEq(amountOut, 0.985 ether);

        // TODO: Check vault accounting when implemented
        // - solverFeeReceiver should have 0.015 ether credited to vault
        // TODO: Check delta accounting when implemented
        // Debit 0.015 from the delta accounting (this means crediting the entire
        // input amount to the delta accounting before running this test, and checking
        // that the value after this test is the amountOut)
    }

    function testTakeFeeAllFeesSet() public {
        uint256 amountIn = 1 ether;
        uint16 solverFeeBps = 200; // 2%
        address solverFeeReceiver = ALICE;
        uint16 routerFeeOnOutputBps = 50; // 0.5%
        uint16 routerFeeOnSolverFeeBps = 500; // 5% of solver fee
        address routerFeeReceiver = BOB;
        address token = WETH_ADDR;

        bytes memory data = abi.encodePacked(
            solverFeeBps,
            solverFeeReceiver,
            routerFeeOnOutputBps,
            routerFeeOnSolverFeeBps,
            routerFeeReceiver,
            token
        );

        uint256 amountOut = feeTakerExposed.takeFee(amountIn, data);

        // 1. solverFee = 1 ether * 200 / 10000 = 0.02 ether
        //    amountAfterSolverFee = 1 ether - 0.02 ether = 0.98 ether
        // 2. routerFeeOnOutput = 0.98 ether * 50 / 10000 = 0.0049 ether
        //    amountAfterRouterFeeOnOutput = 0.98 ether - 0.0049 ether = 0.9751 ether
        // 3. routerFeeOnSolverFee = 0.02 ether * 500 / 10000 = 0.001 ether
        //    amountOut = 0.9751 ether - 0.001 ether = 0.9741 ether
        uint256 solverFee = amountIn * solverFeeBps / 10000;
        uint256 amountAfterSolverFee = amountIn - solverFee;
        uint256 routerFeeOnOutput =
            amountAfterSolverFee * routerFeeOnOutputBps / 10000;
        uint256 routerFeeOnSolverFee =
            solverFee * routerFeeOnSolverFeeBps / 10000;
        uint256 expectedAmountOut =
            amountAfterSolverFee - routerFeeOnOutput - routerFeeOnSolverFee;

        assertEq(amountOut, expectedAmountOut);
        assertEq(amountOut, 0.9741 ether);

        // TODO: Check vault accounting when implemented
        // - solverFeeReceiver should have 0.02 ether credited
        // - routerFeeReceiver should have 0.0059 ether (0.0049 + 0.001) credited
        // TODO: Check delta accounting when implemented
        // Debit 0.015 from the delta accounting (this means crediting the entire
        // input amount to the delta accounting before running this test, and checking
        // that the value after this test is the amountOut)
    }

    function testTakeFeeSolverFeeTooHigh() public {
        // Test with solver fee > 100%
        uint256 amountIn = 1 ether;
        uint16 solverFeeBps = 10001; // 100.01% - too high
        address solverFeeReceiver = ALICE;
        uint16 routerFeeOnOutputBps = 0;
        uint16 routerFeeOnSolverFeeBps = 0;
        address routerFeeReceiver = address(0);
        address token = WETH_ADDR;

        bytes memory data = abi.encodePacked(
            solverFeeBps,
            solverFeeReceiver,
            routerFeeOnOutputBps,
            routerFeeOnSolverFeeBps,
            routerFeeReceiver,
            token
        );

        vm.expectRevert(abi.encodeWithSelector(FeeTaker__FeeTooHigh.selector));
        feeTakerExposed.takeFee(amountIn, data);
    }

    function testTakeFeeRouterFeeOnOutputTooHigh() public {
        // Test with router fee on output > 100%
        uint256 amountIn = 1 ether;
        uint16 solverFeeBps = 0;
        address solverFeeReceiver = address(0);
        uint16 routerFeeOnOutputBps = 10001; // 100.01% - too high
        uint16 routerFeeOnSolverFeeBps = 0;
        address routerFeeReceiver = BOB;
        address token = WETH_ADDR;

        bytes memory data = abi.encodePacked(
            solverFeeBps,
            solverFeeReceiver,
            routerFeeOnOutputBps,
            routerFeeOnSolverFeeBps,
            routerFeeReceiver,
            token
        );

        vm.expectRevert(abi.encodeWithSelector(FeeTaker__FeeTooHigh.selector));
        feeTakerExposed.takeFee(amountIn, data);
    }

    function testTakeFeeRouterFeeOnSolverFeeTooHigh() public {
        // Test with router fee on solver fee > 100%
        uint256 amountIn = 1 ether;
        uint16 solverFeeBps = 100;
        address solverFeeReceiver = ALICE;
        uint16 routerFeeOnOutputBps = 0;
        uint16 routerFeeOnSolverFeeBps = 10001; // 100.01% - too high
        address routerFeeReceiver = BOB;
        address token = WETH_ADDR;

        bytes memory data = abi.encodePacked(
            solverFeeBps,
            solverFeeReceiver,
            routerFeeOnOutputBps,
            routerFeeOnSolverFeeBps,
            routerFeeReceiver,
            token
        );

        vm.expectRevert(abi.encodeWithSelector(FeeTaker__FeeTooHigh.selector));
        feeTakerExposed.takeFee(amountIn, data);
    }
}
