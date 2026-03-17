pragma solidity ^0.8.26;

import {IExecutor} from "@interfaces/IExecutor.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {TransferManager} from "../TransferManager.sol";

error RocketpoolExecutor__InvalidDataLength();

contract RocketpoolExecutor is IExecutor {
    using SafeERC20 for IRocketTokenRETH;

    IRocketTokenRETH public constant RETH =
        IRocketTokenRETH(0xae78736Cd615f374D3085123A210448E74Fc6393);
    IRocketDepositPool public immutable rocketDepositPool;

    constructor(address _rocketDepositPool) {
        rocketDepositPool = IRocketDepositPool(_rocketDepositPool);
    }

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
            // ETH -> rETH: Deposit ETH to Rocketpool to receive rETH
            // We don't need to _transfer ETH into this contract since it must be sent along with the call
            uint256 rethBefore = RETH.balanceOf(address(this));
            rocketDepositPool.deposit{value: amountIn}();
            amountOut = RETH.balanceOf(address(this)) - rethBefore;
            tokenOut = address(RETH);
        } else {
            tokenOut = address(0);
            // rETH -> ETH: Burn rETH to receive ETH
            uint256 ethBefore = address(this).balance;
            RETH.burn(amountIn);
            amountOut = address(this).balance - ethBefore;
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
            TransferManager.TransferType transferType,
            address receiver,
            address tokenIn,
            address tokenOut,
            bool outputToRouter
        )
    {
        if (data.length != 1) {
            revert RocketpoolExecutor__InvalidDataLength();
        }

        bool isDeposit = uint8(data[0]) == 1;
        if (isDeposit) {
            tokenIn = address(0);
            tokenOut = address(RETH);
            transferType = TransferManager.TransferType.TransferNativeInExecutor;
        } else {
            tokenIn = address(RETH);
            tokenOut = address(0);
            transferType = TransferManager.TransferType.ProtocolWillDebit;
        }
        outputToRouter = true;
        // Since burning withdraws the funds from the msg.sender, the user's funds need to be sent to the
        // TychoRouter initially. This does not require an actual approval since our
        // router is interacting directly with the token contract.
        // We use msg.sender (the TychoRouter) instead of address(this) because
        // getTransferData is called via staticcall.
        receiver = msg.sender;
    }
}

interface IRocketDepositPool {
    function deposit() external payable;
}

interface IRocketTokenRETH is IERC20 {
    function burn(uint256 rethAmount) external;
}
