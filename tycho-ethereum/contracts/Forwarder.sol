// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @title Token Forwarder
/// @notice Injected at the settlement address via eth_call code override.
/// Proxies transfer and approve calls so the Analyzer can simulate
/// outbound transfers from the settlement address.
/// @dev Compiled with solc 0.8.27 --via-ir --optimize --optimize-runs 200.
/// Runtime bytecode is embedded as a constant in token_analyzer_ethcall.rs.
contract Forwarder {
    function forwardTransfer(address token, address to, uint256 amount) external returns (bool) {
        return IERC20(token).transfer(to, amount);
    }

    function forwardApprove(address token, address spender, uint256 amount) external returns (bool) {
        return IERC20(token).approve(spender, amount);
    }
}
