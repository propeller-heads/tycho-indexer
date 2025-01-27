// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "@src/CallbackVerificationDispatcher.sol";
import "./TychoRouterTestSetup.sol";

contract CallbackVerificationDispatcherExposed is
    CallbackVerificationDispatcher
{
    function exposedCallVerifier(bytes calldata data)
        external
        returns (
            uint256 amountOwed,
            uint256 amountReceived,
            address tokenOwed,
            uint16 dataOffset
        )
    {
        return _callVerifyCallback(data);
    }

    function exposedDecodeVerifierAndSelector(bytes calldata data)
        external
        pure
        returns (address executor, bytes4 selector, bytes memory protocolData)
    {
        return _decodeVerifierAndSelector(data);
    }

    function exposedSetCallbackVerifier(address target) external {
        _setCallbackVerifier(target);
    }

    function exposedRemoveCallbackVerifier(address target) external {
        _removeCallbackVerifier(target);
    }
}

contract CallbackVerificationDispatcherTest is Constants {
    CallbackVerificationDispatcherExposed dispatcherExposed;

    event CallbackVerifierSet(address indexed callbackVerifier);
    event CallbackVerifierRemoved(address indexed callbackVerifier);

    function setUp() public {
        uint256 forkBlock = 20673900;
        vm.createSelectFork(vm.rpcUrl("mainnet"), forkBlock);
        dispatcherExposed = new CallbackVerificationDispatcherExposed();
        deal(WETH_ADDR, address(dispatcherExposed), 15 ether);
        deployDummyContract();
    }

    function testSetValidVerifier() public {
        vm.expectEmit();
        // Define the event we expect to be emitted at the next step
        emit CallbackVerifierSet(DUMMY);
        dispatcherExposed.exposedSetCallbackVerifier(DUMMY);
        assert(dispatcherExposed.callbackVerifiers(DUMMY) == true);
    }

    function testRemoveVerifier() public {
        dispatcherExposed.exposedSetCallbackVerifier(DUMMY);
        vm.expectEmit();
        // Define the event we expect to be emitted at the next step
        emit CallbackVerifierRemoved(DUMMY);
        dispatcherExposed.exposedRemoveCallbackVerifier(DUMMY);
        assert(dispatcherExposed.callbackVerifiers(DUMMY) == false);
    }

    function testRemoveUnSetVerifier() public {
        dispatcherExposed.exposedRemoveCallbackVerifier(BOB);
        assert(dispatcherExposed.callbackVerifiers(BOB) == false);
    }

    function testSetVerifierNonContract() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                CallbackVerificationDispatcher__NonContractVerifier.selector
            )
        );
        dispatcherExposed.exposedSetCallbackVerifier(BOB);
    }

    function testCallVerifierSuccess() public {
        // For this test, we can use any callback verifier and any calldata that we
        // know works for this verifier. We don't care about which calldata/executor,
        // since we are only testing the functionality of the staticcall and not
        // the inner verifier.
        // Thus, this test case designed from scratch using previously-deployed
        // Maverick callback verifier. Looking at the code, we can easily design
        // passing calldata.
        dispatcherExposed.exposedSetCallbackVerifier(
            address(0x2C960bD1CFE09A26105ad3C351bEa0a3fAD0F8e8)
        );
        bytes memory data =
            hex"2C960bD1CFE09A26105ad3C351bEa0a3fAD0F8e876b20f8a0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        vm.startPrank(address(0xD0b2F5018B5D22759724af6d4281AC0B13266360));
        (
            uint256 amountOwed,
            uint256 amountReceived,
            address tokenOwed,
            uint16 dataOffset
        ) = dispatcherExposed.exposedCallVerifier(data);
        vm.stopPrank();

        // The values themselves are irrelevant, we just need to make sure that we
        // correctly parse the expected output of the existing Maverick verifier
        assert(amountOwed == 1);
        assert(amountReceived == 1);
        assert(tokenOwed == address(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48));
        assert(dataOffset == 148);
    }

    function testCallVerifierNoSelector() public {
        // This test is exactly the same as testCallVerifierSuccess, except that the
        // fn selector is not explicitly passed. The test should still pass using the
        // default selector.
        dispatcherExposed.exposedSetCallbackVerifier(
            address(0x2C960bD1CFE09A26105ad3C351bEa0a3fAD0F8e8)
        );

        // Pass all-zero selector. This should default to the verifyCallback selector
        bytes memory data =
            hex"2C960bD1CFE09A26105ad3C351bEa0a3fAD0F8e8000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        vm.startPrank(address(0xD0b2F5018B5D22759724af6d4281AC0B13266360));
        (
            uint256 amountOwed,
            uint256 amountReceived,
            address tokenOwed,
            uint16 dataOffset
        ) = dispatcherExposed.exposedCallVerifier(data);
        vm.stopPrank();

        // The values themselves are irrelevant, we just need to make sure that we
        // correctly parse the expected output of the existing Maverick verifier
        assert(amountOwed == 1);
        assert(amountReceived == 1);
        assert(tokenOwed == address(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48));
        assert(dataOffset == 148);
    }

    function testCallVerifierBadSelector() public {
        // A bad selector is provided to an approved executor - causing the call
        // itself to fail. Make sure this actually reverts.
        dispatcherExposed.exposedSetCallbackVerifier(
            address(0x2C960bD1CFE09A26105ad3C351bEa0a3fAD0F8e8)
        );
        vm.startPrank(address(0xD0b2F5018B5D22759724af6d4281AC0B13266360));
        bytes memory data =
            hex"2C960bD1CFE09A26105ad3C351bEa0a3fAD0F8e8aa0000000000";
        vm.expectRevert(bytes("Callback verification failed"));
        dispatcherExposed.exposedCallVerifier(data);
        vm.stopPrank();
    }

    function testCallVerifierParseRevertMessage() public {
        // Verification should fail because caller is not a Maverick pool
        // Check that we correctly parse the revert message
        dispatcherExposed.exposedSetCallbackVerifier(
            address(0x2C960bD1CFE09A26105ad3C351bEa0a3fAD0F8e8)
        );
        bytes memory data =
            hex"2C960bD1CFE09A26105ad3C351bEa0a3fAD0F8e8000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        vm.expectRevert(
            abi.encodeWithSignature(
                "Error(string)", "Must call from a Maverick Factory Pool"
            )
        );
        dispatcherExposed.exposedCallVerifier(data);
    }

    function testCallVerifierUnapprovedVerifier() public {
        bytes memory data =
            hex"5d622C9053b8FFB1B3465495C8a42E603632bA70aabbccdd1111111111111111";
        vm.expectRevert();
        dispatcherExposed.exposedCallVerifier(data);
    }

    function testDecodeVerifierAndSelector() public {
        bytes memory data =
            hex"2C960bD1CFE09A26105ad3C351bEa0a3fAD0F8e876b20f8aA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        (address executor, bytes4 selector, bytes memory verifierData) =
            dispatcherExposed.exposedDecodeVerifierAndSelector(data);
        assert(executor == address(0x2C960bD1CFE09A26105ad3C351bEa0a3fAD0F8e8));
        assert(selector == bytes4(0x76b20f8a));
        // Direct bytes comparison not supported - must use keccak
        assert(
            keccak256(verifierData)
                == keccak256(hex"A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
        );
    }
}
