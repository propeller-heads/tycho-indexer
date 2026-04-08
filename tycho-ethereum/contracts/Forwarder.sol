// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @title Token Forwarder
/// @notice Injected at the settlement address via eth_call state override. Proxies ERC20 transfer
/// and approve calls so the Analyzer can simulate outbound transfers from the settlement address.
/// @dev Compiled with: solc 0.8.34 --bin-runtime --via-ir --optimize --optimize-runs 200 --no-cbor-metadata
/// Runtime bytecode is embedded as a constant in bytecode.rs.
///
/// forwardTransfer uses a low-level call so that tokens which omit the bool return value (e.g.
/// USDT) are handled correctly. forwardApprove uses the typed interface since approve consistently
/// returns bool across tokens.
contract Forwarder {
    /// @notice Forward an ERC20 transfer from this address (settlement) to a recipient.
    function forwardTransfer(address token, address to, uint256 amount) external returns (bool) {
        (bool ok, bytes memory data) = token.call(
            abi.encodeWithSelector(0xa9059cbb, to, amount)
        );
        return ok && (data.length == 0 || abi.decode(data, (bool)));
    }

    /// @notice Forward an ERC20 approve from this address (settlement) to a spender.
    function forwardApprove(address token, address spender, uint256 amount) external returns (bool) {
        return IERC20(token).approve(spender, amount);
    }
}
