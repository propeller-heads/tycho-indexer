// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

interface ICallback {
    function handleCallback(
        bytes calldata data
    ) external returns (bytes memory result);
}
