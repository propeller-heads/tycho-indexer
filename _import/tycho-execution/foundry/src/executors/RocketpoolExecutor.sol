// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IExecutor} from "../../interfaces/IExecutor.sol";
import {IERC20} from "../../lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "../../lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "../../lib/openzeppelin-contracts/contracts/utils/Address.sol";
import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";

error RocketpoolExecutor__InvalidDataLength();

contract RocketpoolExecutor is IExecutor, RestrictTransferFrom {
    using SafeERC20 for IRocketTokenRETH;

    IRocketTokenRETH public constant RETH =
    IRocketTokenRETH(0xae78736Cd615f374D3085123A210448E74Fc6393);
    IRocketDepositPool public constant ROCKET_DEPOSIT_POOL =
    IRocketDepositPool(0xDD3f50F8A6CafbE9b31a427582963f465E745AF8);

    constructor(address _permit2) RestrictTransferFrom(_permit2) {}

    // slither-disable-next-line locked-ether
    function swap(
        uint256 givenAmount,
        bytes calldata data
    ) external payable returns (uint256 calculatedAmount) {
        (
            bool isDeposit,
            TransferType transferType,
            address receiver
        ) = _decodeData(data);

        if (isDeposit) {
            // ETH -> rETH: Deposit ETH to Rocketpool to receive rETH
            // We don't need to _transfer ETH into this contract since it must be sent along with the call
            uint256 rethBefore = RETH.balanceOf(address(this));
            ROCKET_DEPOSIT_POOL.deposit{value: givenAmount}();
            calculatedAmount = RETH.balanceOf(address(this)) - rethBefore;

            if (receiver != address(this)) {
                RETH.safeTransfer(receiver, calculatedAmount);
            }
        } else {
            // rETH -> ETH: Burn rETH to receive ETH
            // Use _transfer to get rETH into this contract based on transferType
            _transfer(address(this), transferType, address(RETH), givenAmount);

            uint256 ethBefore = address(this).balance;
            RETH.burn(givenAmount);
            calculatedAmount = address(this).balance - ethBefore;

            if (receiver != address(this)) {
                Address.sendValue(payable(receiver), calculatedAmount);
            }
        }
    }

    function _decodeData(
        bytes calldata data
    )
    internal
    pure
    returns (bool isDeposit, TransferType transferType, address receiver)
    {
        if (data.length != 22) {
            revert RocketpoolExecutor__InvalidDataLength();
        }

        isDeposit = uint8(data[0]) == 1;
        transferType = TransferType(uint8(data[1]));
        receiver = address(bytes20(data[2 : 22]));
    }

    /// @dev Required to receive ETH from RETH.burn()
    receive() external payable {}
}

interface IRocketDepositPool {
    function deposit() external payable;
}

interface IRocketTokenRETH is IERC20 {
    function burn(uint256 _rethAmount) external;
}