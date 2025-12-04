// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@interfaces/IExecutor.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";

error LidoExecutor__InvalidDataLength();
error LidoExecutor__InvalidTarget();
error LidoExecutor__InvalidFactory();
error LidoExecutor__InvalidInitCode();
error LidoExecutor__InvalidFee();
error LidoExecutor__InvalidSwapDirection();

interface LidoPool {
    // slither-disable-next-line naming-convention
    function submit(address _referral) external payable returns (uint256);
}

interface LidoWrappedPool {
    // slither-disable-next-line naming-convention
    function wrap(uint256 _stETHAmount) external returns (uint256);

    function unwrap(uint256 _wstETHAmount) external returns (uint256);
}

enum LidoPoolType {
    stETH,
    wstETH
}

enum LidoPoolDirection {
    Stake,
    Wrap,
    Unwrap
}

contract LidoExecutor is IExecutor, RestrictTransferFrom {
    using SafeERC20 for IERC20;

    address public immutable st_eth;
    address public immutable wst_eth;

    constructor(
        address _st_eth_address,
        address _wst_eth_address,
        address _permit2
    ) RestrictTransferFrom(_permit2) {
        st_eth = _st_eth_address;
        wst_eth = _wst_eth_address;
    }

    // slither-disable-next-line locked-ether
    function swap(
        uint256 givenAmount,
        bytes calldata data //abi packed encoded
    ) external payable returns (uint256 calculatedAmount) {
        IERC20 tokenIn;
        address target;
        address receiver;
        TransferType transferType;
        LidoPoolType pool;
        LidoPoolDirection direction;

        (receiver, transferType, pool, direction) = _decodeData(data);

        _transfer(target, transferType, address(tokenIn), givenAmount);

        if (
            pool == LidoPoolType.stETH && direction == LidoPoolDirection.Stake
        ) {
            //steth, eth -> steth
            LidoPool(st_eth).submit{value: givenAmount}(receiver);
        } else if (
            pool == LidoPoolType.wstETH && direction == LidoPoolDirection.Wrap
        ) {
            //steth, steth -> wsteth
            LidoWrappedPool(wst_eth).wrap(givenAmount);
        } else if (
            pool == LidoPoolType.wstETH && direction == LidoPoolDirection.Unwrap
        ) {
            //wsteth, wsteth -> steth
            LidoWrappedPool(wst_eth).unwrap(givenAmount);
        } else {
            revert LidoExecutor__InvalidSwapDirection();
        }
    }

    function _decodeData(
        bytes calldata data
    )
        internal
        pure
        returns (
            address receiver,
            TransferType transferType,
            LidoPoolType pool,
            LidoPoolDirection direction
        )
    {
        if (data.length != 23) {
            // TODO: double check the length
            revert LidoExecutor__InvalidDataLength();
        }

        receiver = address(bytes20(data[0:20]));
        transferType = TransferType(uint8(data[20]));
        pool = LidoPoolType(uint8(data[21]));
        direction = LidoPoolDirection(uint8(data[22]));
    }
}
