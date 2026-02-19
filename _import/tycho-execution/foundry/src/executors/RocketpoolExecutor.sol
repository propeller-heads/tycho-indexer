// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";

error RocketpoolExecutor__InvalidDataLength();

contract RocketpoolExecutor is IExecutor {
    using SafeERC20 for IRocketTokenRETH;

    IRocketTokenRETH public constant RETH =
        IRocketTokenRETH(0xae78736Cd615f374D3085123A210448E74Fc6393);
    IRocketDepositPool public constant ROCKET_DEPOSIT_POOL =
        IRocketDepositPool(0xDD3f50F8A6CafbE9b31a427582963f465E745AF8);

    constructor() {}

    function fundsExpectedAddress(
        bytes calldata /* data */
    )
        external
        view
        returns (address receiver)
    {
        return msg.sender;
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data, address receiver)
        external
        payable
        returns (uint256 amountOut, address tokenOut)
    {
        bool isDeposit;
        (isDeposit) = _decodeData(data);

        if (isDeposit) {
            tokenOut = address(RETH);
            // ETH -> rETH: Deposit ETH to Rocketpool to receive rETH
            // We don't need to _transfer ETH into this contract since it must be sent along with the call
            uint256 rethBefore = RETH.balanceOf(address(this));
            ROCKET_DEPOSIT_POOL.deposit{value: amountIn}();
            amountOut = RETH.balanceOf(address(this)) - rethBefore;

            if (receiver != address(this)) {
                RETH.safeTransfer(receiver, amountOut);
            }
            tokenOut = address(RETH);
        } else {
            tokenOut = address(0);
            // rETH -> ETH: Burn rETH to receive ETH
            uint256 ethBefore = address(this).balance;
            RETH.burn(amountIn);
            amountOut = address(this).balance - ethBefore;

            if (receiver != address(this)) {
                Address.sendValue(payable(receiver), amountOut);
            }
        }
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (bool isDeposit)
    {
        if (data.length != 1) {
            revert RocketpoolExecutor__InvalidDataLength();
        }

        isDeposit = uint8(data[0]) == 1;
    }

    /// @dev Required to receive ETH from RETH.burn()
    receive() external payable {}

    function getTransferData(bytes calldata data)
        external
        payable
        returns (
            RestrictTransferFrom.TransferType transferType,
            address receiver,
            address tokenIn
        )
    {
        if (data.length != 1) {
            revert RocketpoolExecutor__InvalidDataLength();
        }

        bool isDeposit = uint8(data[0]) == 1;
        if (isDeposit) {
            // ETH transfers are handled in the Executor
            tokenIn = address(0);
            transferType =
            RestrictTransferFrom.TransferType.TransferNativeInExecutor;
        } else {
            tokenIn = address(RETH);
            transferType = RestrictTransferFrom.TransferType.ProtocolWillDebit;
        }
        // Since burning withdraws the funds from the msg.sender, the user's funds need to sent to the
        // TychoRouter initially (address(this)). This does not require an actual
        // approval since our router is interacting directly with the token contract.
        receiver = address(this);
    }
}

interface IRocketDepositPool {
    function deposit() external payable;
}

interface IRocketTokenRETH is IERC20 {
    function burn(uint256 rethAmount) external;
}
