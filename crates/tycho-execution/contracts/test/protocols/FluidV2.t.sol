pragma solidity ^0.8.26;

import {FluidV2Executor} from "@src/executors/FluidV2Executor.sol";
import {Constants} from "../Constants.sol";
import {Test} from "forge-std/Test.sol";
import {TransferManager} from "@src/TransferManager.sol";

contract MockFluidDexV2 {
    bytes public lastStartOperationData;
    uint256 public lastOperateDexType;
    uint256 public lastOperateImplementationId;
    bytes public lastOperateData;
    bytes public nextOperateResult = abi.encode(uint256(0), uint256(0), uint256(0));

    struct SettleCall {
        address token;
        int256 supplyAmount;
        int256 borrowAmount;
        int256 storeAmount;
        address to;
        bool isCallback;
        uint256 value;
    }

    SettleCall[] internal _settleCalls;

    function startOperation(bytes calldata data) external payable returns (bytes memory result) {
        lastStartOperationData = data;
        return result;
    }

    function operate(uint256 dexType, uint256 implementationId, bytes memory data)
        external
        returns (bytes memory returnData)
    {
        lastOperateDexType = dexType;
        lastOperateImplementationId = implementationId;
        lastOperateData = data;
        return nextOperateResult;
    }

    function settle(
        address token,
        int256 supplyAmount,
        int256 borrowAmount,
        int256 storeAmount,
        address to,
        bool isCallback
    ) external payable {
        _settleCalls.push(
            SettleCall({
                token: token,
                supplyAmount: supplyAmount,
                borrowAmount: borrowAmount,
                storeAmount: storeAmount,
                to: to,
                isCallback: isCallback,
                value: msg.value
            })
        );
    }

    function setNextOperateResult(bytes memory result) external {
        nextOperateResult = result;
    }

    function settleCallsLength() external view returns (uint256) {
        return _settleCalls.length;
    }

    function settleCall(uint256 index) external view returns (SettleCall memory) {
        return _settleCalls[index];
    }
}

contract FluidV2ExecutorTest is Test, Constants {
    bytes4 internal constant START_OPERATION_CALLBACK_SELECTOR = bytes4(keccak256("startOperationCallback(bytes)"));
    bytes4 internal constant DEX_CALLBACK_SELECTOR = bytes4(keccak256("dexCallback(address,address,uint256)"));
    bytes4 internal constant SWAP_IN_SELECTOR =
        bytes4(keccak256("swapIn(((address,address,uint24,uint24,address),bool,uint256,uint256,bytes))"));

    address internal constant FLUID_NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    MockFluidDexV2 internal dex;
    FluidV2Executor internal executor;

    function setUp() public {
        dex = new MockFluidDexV2();
        executor = new FluidV2Executor(address(dex));
    }

    function _selector(bytes memory data) internal pure returns (bytes4 sel) {
        assembly {
            sel := mload(add(data, 32))
        }
    }

    function testGetTransferData() public {
        bytes memory data =
            abi.encodePacked(uint8(3), address(DAI_ADDR), address(USDC_ADDR), uint24(100), uint24(1), address(0), true);

        (
            TransferManager.TransferType transferType,
            address receiver,
            address tokenIn,
            address tokenOut,
            bool outputToRouter
        ) = executor.getTransferData(data);

        assertEq(uint8(transferType), uint8(TransferManager.TransferType.None));
        assertEq(receiver, address(0));
        assertEq(tokenIn, DAI_ADDR);
        assertEq(tokenOut, USDC_ADDR);
        assertEq(outputToRouter, false);
    }

    function testGetCallbackTransferDataForStartOperationCallback() public {
        bytes memory raw = abi.encodePacked(START_OPERATION_CALLBACK_SELECTOR, abi.encode(bytes("hello")));

        (TransferManager.TransferType transferType, address receiver, address tokenIn, uint256 amount) =
            executor.getCallbackTransferData(raw);

        assertEq(uint8(transferType), uint8(TransferManager.TransferType.None));
        assertEq(receiver, address(0));
        assertEq(tokenIn, address(0));
        assertEq(amount, 0);
    }

    function testGetCallbackTransferDataForDexCallback() public {
        address recipient = makeAddr("recipient");
        bytes memory raw = abi.encodePacked(DEX_CALLBACK_SELECTOR, abi.encode(DAI_ADDR, recipient, 123));

        (TransferManager.TransferType transferType, address receiver, address tokenIn, uint256 amount) =
            executor.getCallbackTransferData(raw);

        assertEq(uint8(transferType), uint8(TransferManager.TransferType.Transfer));
        assertEq(receiver, recipient);
        assertEq(tokenIn, DAI_ADDR);
        assertEq(amount, 123);
    }

    function testGetCallbackTransferDataForNativeDexCallback() public {
        address recipient = makeAddr("recipient");
        bytes memory raw = abi.encodePacked(DEX_CALLBACK_SELECTOR, abi.encode(FLUID_NATIVE_TOKEN, recipient, 456));

        (TransferManager.TransferType transferType, address receiver, address tokenIn, uint256 amount) =
            executor.getCallbackTransferData(raw);

        assertEq(uint8(transferType), uint8(TransferManager.TransferType.TransferNativeInExecutor));
        assertEq(receiver, recipient);
        assertEq(tokenIn, address(0));
        assertEq(amount, 456);
    }

    function testSwapCallsStartOperation() public {
        address receiver = makeAddr("receiver");
        bytes memory data = abi.encodePacked(
            uint8(3), address(DAI_ADDR), address(USDC_ADDR), uint24(100), uint24(1), address(0), true, hex"beef"
        );

        executor.swap(1e18, data, receiver);

        (
            uint8 dexType,
            DexKey memory dexKey,
            bool swap0To1,
            uint256 amountIn,
            address callbackReceiver,
            bytes memory controllerData
        ) = abi.decode(dex.lastStartOperationData(), (uint8, DexKey, bool, uint256, address, bytes));

        assertEq(dexType, 3);
        assertEq(dexKey.token0, DAI_ADDR);
        assertEq(dexKey.token1, USDC_ADDR);
        assertEq(dexKey.fee, 100);
        assertEq(dexKey.tickSpacing, 1);
        assertEq(dexKey.controller, address(0));
        assertEq(swap0To1, true);
        assertEq(amountIn, 1e18);
        assertEq(callbackReceiver, receiver);
        assertEq(controllerData, hex"beef");
    }

    function testHandleCallbackStartOperationD3() public {
        dex.setNextOperateResult(abi.encode(uint256(900), uint256(11), uint256(22)));

        bytes memory callbackData = abi.encode(
            uint8(3), (DAI_ADDR, USDC_ADDR, uint24(100), uint24(1), address(0)), true, uint256(1000), BOB, bytes("")
        );

        vm.prank(address(dex));
        bytes memory result =
            executor.handleCallback(abi.encodePacked(START_OPERATION_CALLBACK_SELECTOR, abi.encode(callbackData)));

        bytes memory swapResult = abi.decode(result, (bytes));
        assertEq(swapResult, abi.encode(uint256(900), uint256(11), uint256(22)));
        assertEq(dex.lastOperateDexType(), 3);
        assertEq(dex.lastOperateImplementationId(), 1);
        assertEq(_selector(dex.lastOperateData()), SWAP_IN_SELECTOR);
        assertEq(dex.settleCallsLength(), 2);

        MockFluidDexV2.SettleCall memory input = dex.settleCall(0);
        assertEq(input.token, DAI_ADDR);
        assertEq(input.supplyAmount, 1000);
        assertEq(input.borrowAmount, 0);
        assertEq(input.storeAmount, 0);
        assertEq(input.to, BOB);
        assertEq(input.isCallback, true);

        MockFluidDexV2.SettleCall memory output = dex.settleCall(1);
        assertEq(output.token, USDC_ADDR);
        assertEq(output.supplyAmount, -int256(900));
        assertEq(output.borrowAmount, 0);
        assertEq(output.storeAmount, 0);
        assertEq(output.to, BOB);
        assertEq(output.isCallback, true);
    }

    function testHandleCallbackStartOperationD4() public {
        dex.setNextOperateResult(abi.encode(uint256(700), uint256(10), uint256(20)));

        bytes memory callbackData = abi.encode(
            uint8(4), (DAI_ADDR, USDC_ADDR, uint24(100), uint24(1), address(0)), true, uint256(1000), BOB, bytes("")
        );

        vm.prank(address(dex));
        bytes memory result =
            executor.handleCallback(abi.encodePacked(START_OPERATION_CALLBACK_SELECTOR, abi.encode(callbackData)));

        bytes memory swapResult = abi.decode(result, (bytes));
        assertEq(swapResult, abi.encode(uint256(700), uint256(10), uint256(20)));
        assertEq(dex.settleCallsLength(), 2);

        MockFluidDexV2.SettleCall memory input = dex.settleCall(0);
        assertEq(input.token, DAI_ADDR);
        assertEq(input.supplyAmount, 0);
        assertEq(input.borrowAmount, -int256(1000));
        assertEq(input.storeAmount, 0);
        assertEq(input.to, BOB);
        assertEq(input.isCallback, true);

        MockFluidDexV2.SettleCall memory output = dex.settleCall(1);
        assertEq(output.token, USDC_ADDR);
        assertEq(output.supplyAmount, 30);
        assertEq(output.borrowAmount, 730);
        assertEq(output.storeAmount, 0);
        assertEq(output.to, BOB);
        assertEq(output.isCallback, true);
    }

    function testHandleCallbackDexCallbackReturnsEmptyBytes() public {
        vm.prank(address(dex));
        bytes memory result =
            executor.handleCallback(abi.encodePacked(DEX_CALLBACK_SELECTOR, abi.encode(DAI_ADDR, BOB, 123)));

        bytes memory callbackResult = abi.decode(result, (bytes));
        assertEq(callbackResult.length, 0);
    }

    function testVerifyCallbackBadSender() public {
        vm.expectRevert();
        executor.verifyCallback(abi.encodePacked(START_OPERATION_CALLBACK_SELECTOR, abi.encode(bytes(""))));
    }
}
