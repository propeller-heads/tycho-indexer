// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

interface ICallback {
    error UnauthorizedCaller(string exchange, address sender);

    function handleCallback(
        bytes calldata data
    ) external returns (bytes memory result);
}
