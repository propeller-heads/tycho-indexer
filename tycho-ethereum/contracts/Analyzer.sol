// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IForwarder {
    function forwardTransfer(address token, address to, uint256 amount) external returns (bool);
    function forwardApprove(address token, address spender, uint256 amount) external returns (bool);
}

/// @title Token Analyzer
/// @notice Injected at the token holder's address via eth_call code override.
/// Simulates a full round-trip transfer (holder -> settlement -> recipient)
/// and reports balances, gas costs, and success flags.
/// @dev Compiled with solc 0.8.27 --via-ir --optimize --optimize-runs 200.
/// Runtime bytecode is embedded as a constant in token_analyzer_ethcall.rs.
contract Analyzer {
    function analyze(
        address token,
        uint256 amount,
        address settlement,
        address recipient
    ) external returns (
        bool transferInOk,
        bool transferOutOk,
        bool approvalOk,
        uint256 balanceBeforeIn,
        uint256 balanceAfterIn,
        uint256 balanceAfterOut,
        uint256 recipientBefore,
        uint256 recipientAfter,
        uint256 gasIn,
        uint256 gasOut
    ) {
        IERC20 erc20 = IERC20(token);

        // Get balances before
        balanceBeforeIn = erc20.balanceOf(settlement);
        recipientBefore = erc20.balanceOf(recipient);

        // Transfer from holder (this address) to settlement
        uint256 g1 = gasleft();
        try erc20.transfer(settlement, amount) returns (bool success) {
            transferInOk = success;
        } catch {
            transferInOk = false;
        }
        gasIn = g1 - gasleft();

        if (!transferInOk) {
            return (false, false, false, balanceBeforeIn, 0, 0, recipientBefore, 0, gasIn, 0);
        }

        // Get balance of settlement after transfer in
        balanceAfterIn = erc20.balanceOf(settlement);

        // Calculate received amount (handles fee-on-transfer)
        uint256 received = balanceAfterIn - balanceBeforeIn;

        // Transfer from settlement to recipient via forwarder
        uint256 g2 = gasleft();
        try IForwarder(settlement).forwardTransfer(token, recipient, received) returns (bool success) {
            transferOutOk = success;
        } catch {
            transferOutOk = false;
        }
        gasOut = g2 - gasleft();

        if (!transferOutOk) {
            balanceAfterOut = erc20.balanceOf(settlement);
            return (true, false, false, balanceBeforeIn, balanceAfterIn, balanceAfterOut, recipientBefore, 0, gasIn, gasOut);
        }

        // Get balances after transfer out
        balanceAfterOut = erc20.balanceOf(settlement);
        recipientAfter = erc20.balanceOf(recipient);

        // Test approval
        try IForwarder(settlement).forwardApprove(token, recipient, type(uint256).max) returns (bool success) {
            approvalOk = success;
        } catch {
            approvalOk = false;
        }
    }
}
