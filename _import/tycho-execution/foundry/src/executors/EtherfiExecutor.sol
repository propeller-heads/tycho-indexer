pragma solidity ^0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IExecutor} from "@interfaces/IExecutor.sol";
import {TransferManager} from "../TransferManager.sol";

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
            // eETH is share-based and rounds down on amount conversions;
            // cap redeem amount to current balance to avoid 1-wei dust reverts.
            uint256 redeemAmount = IERC20(eethAddress).balanceOf(address(this));
            if (redeemAmount > amountIn) {
                redeemAmount = amountIn;
            }
            uint256 balanceBefore = address(this).balance;
            IEtherfiRedemptionManager(redemptionManagerAddress)
                .redeemEEth(redeemAmount, address(this), ethAddress);
            amountOut = address(this).balance - balanceBefore;
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
        } else if (direction == EtherfiDirection.EethToWeeth) {
            amountOut = IWeETH(weethAddress).wrap(amountIn);
            tokenOut = weethAddress;
        } else if (direction == EtherfiDirection.WeethToEeth) {
            amountOut = IWeETH(weethAddress).unwrap(amountIn);
            tokenOut = eethAddress;
        } else {
            revert EtherfiExecutor__InvalidDirection();
        }
    }

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
        EtherfiDirection direction = _decodeData(data);

        outputToRouter = true;

        if (direction == EtherfiDirection.EthToEeth) {
            transferType = TransferManager.TransferType.TransferNativeInExecutor;
            tokenOut = eethAddress;
        } else if (direction == EtherfiDirection.EethToEth) {
            transferType = TransferManager.TransferType.ProtocolWillDebit;
            receiver = redemptionManagerAddress;
            tokenIn = eethAddress;
            tokenOut = address(0);
        } else if (direction == EtherfiDirection.EethToWeeth) {
            transferType = TransferManager.TransferType.ProtocolWillDebit;
            receiver = weethAddress;
            tokenIn = eethAddress;
            tokenOut = weethAddress;
        } else if (direction == EtherfiDirection.WeethToEeth) {
            transferType = TransferManager.TransferType.ProtocolWillDebit;
            receiver = msg.sender;
            tokenIn = weethAddress;
            tokenOut = eethAddress;
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
