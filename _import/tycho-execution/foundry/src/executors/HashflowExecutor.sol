// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "../RestrictTransferFrom.sol";
import "@interfaces/IExecutor.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

error HashflowExecutor__InvalidHashflowRouter();
error HashflowExecutor__InvalidDataLength();

interface IHashflowRouter {
    struct RFQTQuote {
        address pool;
        address externalAccount;
        address trader;
        address effectiveTrader;
        address baseToken;
        address quoteToken;
        uint256 effectiveBaseTokenAmount;
        uint256 baseTokenAmount;
        uint256 quoteTokenAmount;
        uint256 quoteExpiry;
        uint256 nonce;
        bytes32 txid;
        bytes signature; // ECDSA signature of the quote, 65 bytes
    }

    function tradeRFQT(RFQTQuote calldata quote) external payable;
}

contract HashflowExecutor is IExecutor, RestrictTransferFrom {
    using SafeERC20 for IERC20;

    address public constant NATIVE_TOKEN =
        0x0000000000000000000000000000000000000000;

    /// @notice The Hashflow router address
    address public immutable hashflowRouter;

    constructor(address _hashflowRouter, address _permit2)
        RestrictTransferFrom(_permit2)
    {
        if (_hashflowRouter == address(0)) {
            revert HashflowExecutor__InvalidHashflowRouter();
        }
        hashflowRouter = _hashflowRouter;
    }

    function swap(uint256 givenAmount, bytes calldata data)
        external
        payable
        returns (uint256 calculatedAmount)
    {
        (
            IHashflowRouter.RFQTQuote memory quote,
            bool approvalNeeded,
            TransferType transferType
        ) = _decodeData(data);

        // Slippage checks
        if (givenAmount > quote.baseTokenAmount) {
            // Do not transfer more than the quote's maximum permitted amount.
            givenAmount = quote.baseTokenAmount;
        }
        quote.effectiveBaseTokenAmount = givenAmount;

        if (approvalNeeded && quote.baseToken != NATIVE_TOKEN) {
            // slither-disable-next-line unused-return
            IERC20(quote.baseToken).forceApprove(
                hashflowRouter, type(uint256).max
            );
        }

        uint256 ethValue = 0;
        if (quote.baseToken == NATIVE_TOKEN) {
            ethValue = quote.effectiveBaseTokenAmount;
        }
        _transfer(
            address(this), transferType, address(quote.baseToken), givenAmount
        );
        uint256 balanceBefore = _balanceOf(quote.trader, quote.quoteToken);
        IHashflowRouter(hashflowRouter).tradeRFQT{value: ethValue}(quote);
        uint256 balanceAfter = _balanceOf(quote.trader, quote.quoteToken);
        calculatedAmount = balanceAfter - balanceBefore;
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (
            IHashflowRouter.RFQTQuote memory quote,
            bool approvalNeeded,
            TransferType transferType
        )
    {
        if (data.length != 327) {
            revert HashflowExecutor__InvalidDataLength();
        }

        transferType = TransferType(uint8(data[0]));
        approvalNeeded = data[1] != 0;

        quote.pool = address(bytes20(data[2:22]));
        quote.externalAccount = address(bytes20(data[22:42]));
        quote.trader = address(bytes20(data[42:62]));
        // Assumes we never set the effectiveTrader when requesting a quote.
        quote.effectiveTrader = quote.trader;
        quote.baseToken = address(bytes20(data[62:82]));
        quote.quoteToken = address(bytes20(data[82:102]));
        // Not included in the calldata. Will be set in the swap function.
        quote.effectiveBaseTokenAmount = 0;
        quote.baseTokenAmount = uint256(bytes32(data[102:134]));
        quote.quoteTokenAmount = uint256(bytes32(data[134:166]));
        quote.quoteExpiry = uint256(bytes32(data[166:198]));
        quote.nonce = uint256(bytes32(data[198:230]));
        quote.txid = bytes32(data[230:262]);
        quote.signature = data[262:327];
    }

    function _balanceOf(address trader, address token)
        internal
        view
        returns (uint256 balance)
    {
        balance = token == NATIVE_TOKEN
            ? trader.balance
            : IERC20(token).balanceOf(trader);
    }
}
