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
            address routerFeeReceiver
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
        bytes memory data = abi.encodePacked(
            expectedSolverFeeBps, // 2 bytes
            expectedSolverFeeReceiver, // 20 bytes
            expectedRouterFeeOnOutputBps, // 2 bytes
            expectedRouterFeeOnSolverFeeBps, // 2 bytes
            expectedRouterFeeReceiver // 20 bytes
        );
        (
            uint16 solverFeeBps,
            address solverFeeReceiver,
            uint16 routerFeeOnOutputBps,
            uint16 routerFeeOnSolverFeeBps,
            address routerFeeReceiver
        ) = feeTakerExposed.decodeFeeData(data);

        assertEq(solverFeeBps, expectedSolverFeeBps);
        assertEq(solverFeeReceiver, expectedSolverFeeReceiver);
        assertEq(routerFeeOnOutputBps, expectedRouterFeeOnOutputBps);
        assertEq(routerFeeOnSolverFeeBps, expectedRouterFeeOnSolverFeeBps);
        assertEq(routerFeeReceiver, expectedRouterFeeReceiver);
    }

    function testDecodeFeeDataInvalidLength() public {
        // Test with data that's too short (45 bytes instead of 46)
        bytes memory data = new bytes(45);
        vm.expectRevert(
            abi.encodeWithSelector(FeeTaker__InvalidDataLength.selector)
        );
        feeTakerExposed.decodeFeeData(data);
    }

    function testTakeFeeOnlyRouterFeeOnOutput() public view {
        // Test with only router fee on output set
        uint256 amountIn = 1 ether;
        uint16 solverFeeBps = 0;
        address solverFeeReceiver = address(0);
        uint16 routerFeeOnOutputBps = 100; // 1%
        uint16 routerFeeOnSolverFeeBps = 0;
        address routerFeeReceiver = BOB;

        bytes memory data = abi.encodePacked(
            solverFeeBps,
            solverFeeReceiver,
            routerFeeOnOutputBps,
            routerFeeOnSolverFeeBps,
            routerFeeReceiver
        );

        (
            uint256 amountOut,
            uint256 routerFee,
            address returnedRouterFeeReceiver,
            uint256 solverFee,
            address returnedSolverFeeReceiver
        ) = feeTakerExposed.takeFee(amountIn, data);

        // routerFeeOnOutput = 1 ether * 100 / 10000 = 0.01 ether
        // amountOut = 1 ether - 0.01 ether = 0.99 ether
        assertEq(amountOut, 0.99 ether);
        assertEq(routerFee, 0.01 ether);
        assertEq(returnedRouterFeeReceiver, routerFeeReceiver);
        assertEq(solverFee, 0);
        assertEq(returnedSolverFeeReceiver, solverFeeReceiver);
    }

    function testTakeFeeOnlyRouterFeeOnSolverFee() public view {
        // Test with only router fee on solver fee set (requires solver fee to be set too)
        uint256 amountIn = 1 ether;
        uint16 solverFeeBps = 200; // 2%
        address solverFeeReceiver = ALICE;
        uint16 routerFeeOnOutputBps = 0;
        uint16 routerFeeOnSolverFeeBps = 1000; // 10% of solver fee
        address routerFeeReceiver = BOB;

        bytes memory data = abi.encodePacked(
            solverFeeBps,
            solverFeeReceiver,
            routerFeeOnOutputBps,
            routerFeeOnSolverFeeBps,
            routerFeeReceiver
        );

        (
            uint256 amountOut,
            uint256 routerFee,
            address returnedRouterFeeReceiver,
            uint256 solverFee,
            address returnedSolverFeeReceiver
        ) = feeTakerExposed.takeFee(amountIn, data);

        // solverFee = 1 ether * 200 / 10000 = 0.02 ether
        // routerFeeOnSolverFee = 0.02 ether * 1000 / 10000 = 0.002 ether
        // solverPortion = 0.02 - 0.002 = 0.018 ether
        // amountOut = 1 ether - 0.02 ether = 0.98 ether
        assertEq(amountOut, 0.98 ether);
        assertEq(routerFee, 0.002 ether);
        assertEq(returnedRouterFeeReceiver, routerFeeReceiver);
        assertEq(solverFee, 0.018 ether);
        assertEq(returnedSolverFeeReceiver, solverFeeReceiver);
    }

    function testTakeFeeOnlySolverFee() public view {
        // Test with only solver fee set, no router fees
        uint256 amountIn = 1 ether;
        uint16 solverFeeBps = 150; // 1.5%
        address solverFeeReceiver = ALICE;
        uint16 routerFeeOnOutputBps = 0;
        uint16 routerFeeOnSolverFeeBps = 0;
        address routerFeeReceiver = address(0);

        bytes memory data = abi.encodePacked(
            solverFeeBps,
            solverFeeReceiver,
            routerFeeOnOutputBps,
            routerFeeOnSolverFeeBps,
            routerFeeReceiver
        );

        (
            uint256 amountOut,
            uint256 routerFee,
            address returnedRouterFeeReceiver,
            uint256 solverFee,
            address returnedSolverFeeReceiver
        ) = feeTakerExposed.takeFee(amountIn, data);

        // solverFee = 1 ether * 150 / 10000 = 0.015 ether
        // amountOut = 1 ether - 0.015 ether = 0.985 ether
        assertEq(amountOut, 0.985 ether);
        assertEq(routerFee, 0);
        assertEq(returnedRouterFeeReceiver, routerFeeReceiver);
        assertEq(solverFee, 0.015 ether);
        assertEq(returnedSolverFeeReceiver, solverFeeReceiver);
    }

    function testTakeFeeAllFeesSet() public view {
        uint256 amountIn = 1 ether;
        uint16 solverFeeBps = 200; // 2%
        address solverFeeReceiver = ALICE;
        uint16 routerFeeOnOutputBps = 50; // 0.5%
        uint16 routerFeeOnSolverFeeBps = 500; // 5% of solver fee
        address routerFeeReceiver = BOB;

        bytes memory data = abi.encodePacked(
            solverFeeBps,
            solverFeeReceiver,
            routerFeeOnOutputBps,
            routerFeeOnSolverFeeBps,
            routerFeeReceiver
        );

        (
            uint256 amountOut,
            uint256 routerFee,
            address returnedRouterFeeReceiver,
            uint256 solverFee,
            address returnedSolverFeeReceiver
        ) = feeTakerExposed.takeFee(amountIn, data);

        // 1. solverFee = 1 ether * 200 / 10000 = 0.02 ether
        //    routerFeeOnSolverFee = 0.02 ether * 500 / 10000 = 0.001 ether
        //    solverPortion = 0.02 - 0.001 = 0.019 ether
        //    amountAfterSolverFee = 1 ether - 0.02 ether = 0.98 ether
        // 2. routerFeeOnOutput = 0.98 ether * 50 / 10000 = 0.0049 ether
        //    amountOut = 0.98 ether - 0.0049 ether = 0.9751 ether
        //    totalRouterFee = 0.001 + 0.0049 = 0.0059 ether
        assertEq(amountOut, 0.9751 ether);
        assertEq(routerFee, 0.0059 ether);
        assertEq(returnedRouterFeeReceiver, routerFeeReceiver);
        assertEq(solverFee, 0.019 ether);
        assertEq(returnedSolverFeeReceiver, solverFeeReceiver);
    }

    function testTakeFeeCombinedFeeTooHigh() public {
        // Test with solver fee + router fee on output > 100%
        uint256 amountIn = 1 ether;
        uint16 solverFeeBps = 5001; // 50.01%
        address solverFeeReceiver = ALICE;
        uint16 routerFeeOnOutputBps = 5000; // 50% - combined this should make 100.01%
        uint16 routerFeeOnSolverFeeBps = 0;
        address routerFeeReceiver = address(0);

        bytes memory data = abi.encodePacked(
            solverFeeBps,
            solverFeeReceiver,
            routerFeeOnOutputBps,
            routerFeeOnSolverFeeBps,
            routerFeeReceiver
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

        bytes memory data = abi.encodePacked(
            solverFeeBps,
            solverFeeReceiver,
            routerFeeOnOutputBps,
            routerFeeOnSolverFeeBps,
            routerFeeReceiver
        );

        vm.expectRevert(abi.encodeWithSelector(FeeTaker__FeeTooHigh.selector));
        feeTakerExposed.takeFee(amountIn, data);
    }
}
