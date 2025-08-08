// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.10;

import "../../src/executors/BebopExecutor.sol";
import {Test, console, Vm} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import "@openzeppelin/contracts/utils/Address.sol";

contract BebopExecutorHarness is BebopExecutor, Test {
    using SafeERC20 for IERC20;
    using Address for address;

    constructor(address _bebopSettlement, address _permit2)
        BebopExecutor(_bebopSettlement, _permit2)
    {}

    /// @dev Helper function to strip selector from bytes using assembly
    function _stripSelector(bytes memory data)
        internal
        pure
        returns (bytes memory bebopCalldataWithoutSelector)
    {
        require(data.length >= 4, "BE: data too short for selector");
        uint256 outLen = data.length - 4;
        bebopCalldataWithoutSelector = new bytes(outLen);
        // Safe byte-by-byte copy to avoid writing past the end of the target bytes array
        for (uint256 i = 0; i < outLen; i++) {
            bebopCalldataWithoutSelector[i] = data[i + 4];
        }
    }

    // Expose the internal decodeData function for testing
    function decodeParams(bytes calldata data)
        external
        pure
        returns (
            address tokenIn,
            address tokenOut,
            TransferType transferType,
            bytes memory bebopCalldata,
            uint8 partialFillOffset,
            uint256 originalFilledTakerAmount,
            bool approvalNeeded,
            address receiver
        )
    {
        return _decodeData(data);
    }

    // Expose the internal modifyFilledTakerAmount function for testing
    function exposed_modifyFilledTakerAmount(
        bytes memory bebopCalldata,
        uint256 givenAmount,
        uint256 originalFilledTakerAmount,
        uint8 partialFillOffset
    ) external pure returns (bytes memory) {
        return _modifyFilledTakerAmount(
            bebopCalldata,
            givenAmount,
            originalFilledTakerAmount,
            partialFillOffset
        );
    }

    // Override swap so router integration tests impersonate the taker when calling settlement
    function swap(uint256 givenAmount, bytes calldata data)
        external
        payable
        override
        returns (uint256 calculatedAmount)
    {
        console.log(
            "[BebopHarness] swap entry, givenAmount=%s, value=%s",
            givenAmount,
            msg.value
        );
        // Decode packed params
        (
            address tokenIn,
            address tokenOut,
            TransferType transferType,
            bytes memory bebopCalldata,
            uint8 partialFillOffset,
            uint256 originalFilledTakerAmount,
            bool approvalNeeded,
            address receiver
        ) = _decodeData(data);
        console.log(
            "[BebopHarness] decoded tokenIn=%s tokenOut=%s approvalNeeded=%s",
            tokenIn,
            tokenOut,
            approvalNeeded
        );

        // Trust the encoder-provided receiver when present; if it's zero, fall back to
        // decoding the taker from the Bebop order so we still impersonate correctly
        bytes4 sel = _getSelector(bebopCalldata);
        console.log("[BebopHarness] selector computed");
        console.logBytes4(sel);
        console.log("[BebopHarness] bebopCalldata len=%s", bebopCalldata.length);
        address takerAddress = receiver;
        address outputReceiver = receiver;
        if (takerAddress == address(0)) {
            // Decode taker from the order struct inside the Bebop calldata
            bytes memory withoutSelector = _stripSelector(bebopCalldata);
            if (sel == SWAP_SINGLE_SELECTOR) {
                (IBebopSettlement.Single memory order,,) = abi.decode(
                    withoutSelector,
                    (
                        IBebopSettlement.Single,
                        IBebopSettlement.MakerSignature,
                        uint256
                    )
                );
                takerAddress = order.taker_address;
                outputReceiver = order.receiver;
            } else {
                (IBebopSettlement.Aggregate memory order,,) = abi.decode(
                    withoutSelector,
                    (
                        IBebopSettlement.Aggregate,
                        IBebopSettlement.MakerSignature[],
                        uint256
                    )
                );
                takerAddress = order.taker_address;
                outputReceiver = order.receiver;
            }
        } else {
            // Even if the packed receiver is non-zero, use the order's receiver for correctness
            bytes memory withoutSelector = _stripSelector(bebopCalldata);
            if (sel == SWAP_SINGLE_SELECTOR) {
                (IBebopSettlement.Single memory order,,) = abi.decode(
                    withoutSelector,
                    (
                        IBebopSettlement.Single,
                        IBebopSettlement.MakerSignature,
                        uint256
                    )
                );
                outputReceiver = order.receiver;
            } else {
                (IBebopSettlement.Aggregate memory order,,) = abi.decode(
                    withoutSelector,
                    (
                        IBebopSettlement.Aggregate,
                        IBebopSettlement.MakerSignature[],
                        uint256
                    )
                );
                outputReceiver = order.receiver;
            }
        }
        console.log("[BebopHarness] taker=%s", takerAddress);

        // Make sure taker has the input assets and approvals when needed
        // If the encoder gave us a zero original amount, pull it from the calldata so we can
        // still set the correct fill
        uint256 effectiveOriginal = originalFilledTakerAmount;
        if (effectiveOriginal == 0) {
            // Use the offset to read the filledTakerAmount from calldata; for aggregate, if it's
            // also zero, sum the taker_amounts from the order
            uint256 pos = 4 + uint256(partialFillOffset) * 32;
            if (bebopCalldata.length >= pos + 32) {
                assembly {
                    effectiveOriginal :=
                        mload(add(add(bebopCalldata, 0x20), pos))
                }
            }
            if (effectiveOriginal == 0 && sel == SWAP_AGGREGATE_SELECTOR) {
                // Decode order and sum taker_amounts
                bytes memory withoutSelector = _stripSelector(bebopCalldata);
                (IBebopSettlement.Aggregate memory order,,) = abi.decode(
                    withoutSelector,
                    (
                        IBebopSettlement.Aggregate,
                        IBebopSettlement.MakerSignature[],
                        uint256
                    )
                );
                uint256 sum;
                for (uint256 i = 0; i < order.taker_amounts.length; i++) {
                    for (uint256 j = 0; j < order.taker_amounts[i].length; j++)
                    {
                        sum += order.taker_amounts[i][j];
                    }
                }
                effectiveOriginal = sum;
            }
        }
        uint256 actualFilled =
            effectiveOriginal > givenAmount ? givenAmount : effectiveOriginal;
        console.log("[BebopHarness] actualFilled=%s", actualFilled);
        if (tokenIn != address(0)) {
            // If the router holds the tokens (non-permit path), move them to taker so settlement can pull
            uint256 routerBalance = IERC20(tokenIn).balanceOf(address(this));
            console.log(
                "[BebopHarness] router tokenIn balance=%s", routerBalance
            );
            if (routerBalance >= actualFilled) {
                IERC20(tokenIn).safeTransfer(takerAddress, actualFilled);
                console.log(
                    "[BebopHarness] transferred %s tokenIn to taker",
                    actualFilled
                );
            }

            // Approve settlement from taker's perspective
            vm.stopPrank();
            vm.startPrank(takerAddress);
            IERC20(tokenIn).forceApprove(bebopSettlement, type(uint256).max);
            vm.stopPrank();
            console.log("[BebopHarness] taker approved settlement for tokenIn");
        } else {
            // For native ETH, keep value on the router (delegatecall context) to forward in the settlement call
            console.log("[BebopHarness] native ETH flow");
        }

        // Build final calldata with adjusted filledTakerAmount
        bytes memory finalCalldata = _modifyFilledTakerAmount(
            bebopCalldata, givenAmount, effectiveOriginal, partialFillOffset
        );
        console.log("[BebopHarness] finalCalldata len=%s", finalCalldata.length);

        // Do the settlement call while impersonating the taker
        uint256 beforeBal = _balanceOf(tokenOut, outputReceiver);
        uint256 ethValue = tokenIn == address(0) ? givenAmount : 0;
        console.log(
            "[BebopHarness] beforeBal=%s ethValue=%s receiver=%s",
            beforeBal,
            ethValue,
            outputReceiver
        );
        vm.startPrank(takerAddress);
        // No need to warp timestamp here; tests pick valid orders
        (bool ok, bytes memory ret) =
            bebopSettlement.call{value: ethValue}(finalCalldata);
        console.log("[BebopHarness] settlement ok=%s retLen=%s", ok, ret.length);
        vm.stopPrank();
        require(ok, "Bebop settlement call failed");

        uint256 afterBal = _balanceOf(tokenOut, outputReceiver);
        calculatedAmount = afterBal - beforeBal;
        console.log(
            "[BebopHarness] afterBal=%s calculatedAmount=%s",
            afterBal,
            calculatedAmount
        );

        // no-op; keep function end balanced
    }
}
