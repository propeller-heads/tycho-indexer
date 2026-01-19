// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {RestrictTransferFrom} from "../RestrictTransferFrom.sol";
import {IExecutor} from "@interfaces/IExecutor.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

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

contract HashflowExecutor is IExecutor {
    using SafeERC20 for IERC20;

    address public constant NATIVE_TOKEN =
        0x0000000000000000000000000000000000000000;

    /// @notice The Hashflow router address
    address public immutable hashflowRouter;

    constructor(address _hashflowRouter) {
        if (_hashflowRouter == address(0)) {
            revert HashflowExecutor__InvalidHashflowRouter();
        }
        hashflowRouter = _hashflowRouter;
    }

    function swap(uint256 amountIn, bytes calldata data)
        external
        payable
        returns (uint256 amountOut, address tokenOut, address receiver)
    {
        (IHashflowRouter.RFQTQuote memory quote, bool approvalNeeded) =
            _decodeData(data);

        // Slippage checks
        if (amountIn > quote.baseTokenAmount) {
            // Do not transfer more than the quote's maximum permitted amount.
            amountIn = quote.baseTokenAmount;
        }
        quote.effectiveBaseTokenAmount = amountIn;

        uint256 ethValue = 0;
        if (quote.baseToken == NATIVE_TOKEN) {
            ethValue = quote.effectiveBaseTokenAmount;
        }

        uint256 balanceBefore = _balanceOf(quote.trader, quote.quoteToken);
        IHashflowRouter(hashflowRouter).tradeRFQT{value: ethValue}(quote);
        uint256 balanceAfter = _balanceOf(quote.trader, quote.quoteToken);
        amountOut = balanceAfter - balanceBefore;
        tokenOut = quote.quoteToken;
        receiver = quote.trader;
    }

    function _decodeData(bytes calldata data)
        internal
        pure
        returns (IHashflowRouter.RFQTQuote memory quote, bool approvalNeeded)
    {
        if (data.length != 327) {
            revert HashflowExecutor__InvalidDataLength();
        }

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

    function getTransferData(bytes calldata data)
        external
        payable
        returns (
            RestrictTransferFrom.TransferType transferType,
            address receiver,
            address tokenIn
        )
    {
        if (data.length != 327) {
            revert HashflowExecutor__InvalidDataLength();
        }

        transferType = RestrictTransferFrom.TransferType(uint8(data[0]));
        tokenIn = address(bytes20(data[62:82]));
        // The receiver of the funds will be the Hashflow Router.
        // This protocol will only ever have the following transferTypes:
        // - TransferFromAndProtocolWillDebit: the funds should be transferred to the TychoRouter and the Hashflow Router needs to be approved
        // - ProtocolWillDebit: Hashflow Router needs to be approved
        receiver = hashflowRouter;
    }
}

//adccf4720000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000002260fac5e5542a773aa44fbcfedf7c193bc2c599000000000000000000000000000000000000000000000000000000000038aebf000000000000000000000000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001c800692e234dae75c793f67a35089c9d99245e1c58470bc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480001f43ede3eca2a72b3aecc820e955b36f38437d0139588e6a0c2ddd26feeb64f039a2c41296fcb3f56400000015b15cf58144ef33af1e14b5208015d11f9143e27b904here01478eca1b93865dca0b9f325935eb123c8a4af011bee3211ab312a8d065c4fef0247448e17a8da000cd09f75e2bf2a4d11f3ab23f1389fcc1621c0cc2a0b86991c6218b36c1d19d4a2e9eb0ce3606eb482260fac5e5542a773aa44fbcfedf7c193bc2c5990000000000000000000000000000000000000000000000000000000100c84f11000000000000000000000000000000000000000000000000000000000038aebf0000000000000000000000000000000000000000000000000000000068a47cd800000000000000000000000000000000000000000000000000000198c286fecb125000064000640000001747eb8c38ffffffffffffff0029642016edb36d00006ddb3b21fe8509e274ddf46c55209cdbf30360944abbca6569ed6b26740d052f419964dcb5a3bdb98b4ed1fb3642a2760b8312118599a962251f7a8f73fe4fbe1c000000000000000000000000000000000000000000000000
