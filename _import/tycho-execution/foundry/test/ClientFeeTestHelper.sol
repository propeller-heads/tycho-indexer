// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {ClientFeeParams} from "@src/TychoRouter.sol";
import {Constants} from "./Constants.sol";

contract ClientFeeTestHelper is Test, Constants {
    bytes32 private constant _CLIENT_FEE_TYPEHASH = keccak256(
        "ClientFee(uint16 clientFeeBps,address clientFeeReceiver,"
        "uint256 maxClientContribution,uint256 deadline)"
    );

    /**
     * @dev Signs a ClientFeeParams struct with the given private key,
     *      producing the EIP-712 signature expected by TychoRouter.
     */
    function signClientFee(
        ClientFeeParams memory params,
        address routerAddress,
        uint256 privateKey
    ) internal view returns (bytes memory signature) {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,"
                    "uint256 chainId,address verifyingContract)"
                ),
                keccak256("TychoRouter"),
                keccak256("1"),
                block.chainid,
                routerAddress
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                _CLIENT_FEE_TYPEHASH,
                params.clientFeeBps,
                params.clientFeeReceiver,
                params.maxClientContribution,
                params.deadline
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    /**
     * @dev Returns an empty ClientFeeParams for calls that do not use client fees.
     */
    function noClientFee()
        internal
        pure
        returns (ClientFeeParams memory params)
    {
        params = ClientFeeParams({
            clientFeeBps: 0,
            clientFeeReceiver: address(0),
            maxClientContribution: 0,
            deadline: 0,
            clientSignature: new bytes(0)
        });
    }

    /**
     * @dev Builds and signs a ClientFeeParams struct using the given private key.
     *      The signer address is derived from the private key and used as clientFeeReceiver.
     */
    function makeClientFeeParams(
        uint16 clientFeeBps,
        uint256 maxClientContribution,
        address routerAddress,
        uint256 privateKey
    ) internal view returns (ClientFeeParams memory params) {
        address receiver = vm.addr(privateKey);
        params = ClientFeeParams({
            clientFeeBps: clientFeeBps,
            clientFeeReceiver: receiver,
            maxClientContribution: maxClientContribution,
            deadline: block.timestamp + 1 hours,
            clientSignature: new bytes(0)
        });
        params.clientSignature =
            signClientFee(params, routerAddress, privateKey);
    }
}
