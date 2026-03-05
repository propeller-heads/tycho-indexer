// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IExecutor} from "@interfaces/IExecutor.sol";
import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";

error EtherfiExecutor__InvalidDataLength();
error EtherfiExecutor__InvalidDirection();

interface IEtherfiRedemptionManager {
    function redeemEEth(
        uint256 eEthAmount,
        address receiver,
        address outputToken
    ) external;
}

interface IEtherfiLiquidityPool {
    function deposit() external payable returns (uint256);
}

interface IWeETH {
    function wrap(uint256 _eETHAmount) external returns (uint256);
    function unwrap(uint256 _weETHAmount) external returns (uint256);
}

enum EtherfiDirection {
    EethToEth,
    EthToEeth,
    EethToWeeth,
    WeethToEeth
}

contract EtherfiExecutor is IExecutor {
    using SafeERC20 for IERC20;

    address public immutable ethAddress;
    address public immutable eethAddress;
    address public immutable liquidityPoolAddress;
    address public immutable weethAddress;
    address public immutable redemptionManagerAddress;

    constructor(
        address _ethAddress,
        address _eethAddress,
        address _liquidityPoolAddress,
        address _weethAddress,
        address _redemptionManagerAddress
    ) {
        require(
            _ethAddress != address(0), "EtherfiExecutor: ethAddress is zero"
        );
        require(
            _eethAddress != address(0), "EtherfiExecutor: eethAddress is zero"
        );
        require(
            _liquidityPoolAddress != address(0),
            "EtherfiExecutor: liquidityPoolAddress is zero"
        );
        require(
            _weethAddress != address(0), "EtherfiExecutor: weethAddress is zero"
        );
        require(
            _redemptionManagerAddress != address(0),
            "EtherfiExecutor: redemptionManagerAddress is zero"
        );

        ethAddress = _ethAddress;
        eethAddress = _eethAddress;
        liquidityPoolAddress = _liquidityPoolAddress;
        weethAddress = _weethAddress;
        redemptionManagerAddress = _redemptionManagerAddress;
    }

    // slither-disable-next-line locked-ether
    function swap(uint256 amountIn, bytes calldata data, address receiver)
        external
        payable
        returns (uint256 amountOut, address tokenOut)
    {
        EtherfiDirection direction;
        direction = _decodeData(data);

        if (direction == EtherfiDirection.EethToEth) {
            uint256 balanceBefore = receiver.balance;
            // eETH is share-based and rounds down on amount conversions;
            // cap redeem amount to current balance to avoid 1-wei dust reverts.
            uint256 redeemAmount = IERC20(eethAddress).balanceOf(address(this));
            if (redeemAmount > amountIn) {
                redeemAmount = amountIn;
            }
            IEtherfiRedemptionManager(redemptionManagerAddress)
                .redeemEEth(redeemAmount, receiver, ethAddress);
            amountOut = receiver.balance - balanceBefore;
            tokenOut = ethAddress;
        } else if (direction == EtherfiDirection.EthToEeth) {
            uint256 balanceBefore = IERC20(eethAddress).balanceOf(address(this));
            // deposit() returns shares, not the eETH amount;
            // use balance delta for amount-out.
            // slither-disable-next-line arbitrary-send-eth,unused-return
            IEtherfiLiquidityPool(liquidityPoolAddress)
            .deposit{value: amountIn}();
            uint256 balanceAfter = IERC20(eethAddress).balanceOf(address(this));
            amountOut = balanceAfter - balanceBefore;
            tokenOut = eethAddress;

            if (receiver != address(this)) {
                uint256 receiverBalanceBefore =
                    IERC20(eethAddress).balanceOf(receiver);
                IERC20(eethAddress).safeTransfer(receiver, amountOut);
                uint256 receiverBalanceAfter =
                    IERC20(eethAddress).balanceOf(receiver);
                amountOut = receiverBalanceAfter - receiverBalanceBefore;
            }
        } else if (direction == EtherfiDirection.EethToWeeth) {
            amountOut = IWeETH(weethAddress).wrap(amountIn);
            tokenOut = weethAddress;

            if (receiver != address(this)) {
                IERC20(weethAddress).safeTransfer(receiver, amountOut);
            }
        } else if (direction == EtherfiDirection.WeethToEeth) {
            amountOut = IWeETH(weethAddress).unwrap(amountIn);
            tokenOut = eethAddress;

            if (receiver != address(this)) {
                IERC20(eethAddress).safeTransfer(receiver, amountOut);
            }
        } else {
            revert EtherfiExecutor__InvalidDirection();
        }
    }

    function getTransferData(bytes calldata data)
        external
        payable
        returns (
            RestrictTransferFrom.TransferType transferType,
            address receiver,
            address tokenIn
        )
    {
        EtherfiDirection direction = _decodeData(data);

        if (direction == EtherfiDirection.EthToEeth) {
            return (
                RestrictTransferFrom.TransferType.TransferNativeInExecutor,
                address(0),
                address(0)
            );
        } else if (direction == EtherfiDirection.EethToEth) {
            // redemptionManager pulls eETH from router via transferFrom
            return (
                RestrictTransferFrom.TransferType.ProtocolWillDebit,
                redemptionManagerAddress,
                eethAddress
            );
        } else if (direction == EtherfiDirection.EethToWeeth) {
            // weETH.wrap() pulls eETH from router via transferFrom
            return (
                RestrictTransferFrom.TransferType.ProtocolWillDebit,
                weethAddress,
                eethAddress
            );
        } else if (direction == EtherfiDirection.WeethToEeth) {
            // weETH.unwrap() burns from router (no transferFrom), so no approval
            // needed — receiver=address(this) skips _approveIfNeeded
            return (
                RestrictTransferFrom.TransferType.ProtocolWillDebit,
                address(this),
                weethAddress
            );
        } else {
            revert EtherfiExecutor__InvalidDirection();
        }
    }

    function fundsExpectedAddress(
        bytes calldata /* data */
    )
        external
        view
        returns (address)
    {
        return msg.sender;
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (EtherfiDirection direction)
    {
        if (data.length != 1) {
            revert EtherfiExecutor__InvalidDataLength();
        }
        direction = EtherfiDirection(uint8(data[0]));
    }
}
