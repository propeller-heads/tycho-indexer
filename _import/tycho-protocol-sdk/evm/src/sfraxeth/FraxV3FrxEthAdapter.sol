// SPDX-License-Identifier: AGPL-3.0-or-later
pragma experimental ABIEncoderV2;
pragma solidity ^0.8.13;

import {ISwapAdapter} from "src/interfaces/ISwapAdapter.sol";
import {
    IERC20,
    ERC20
} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {SafeERC20} from
    "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";

library FixedPointMathLib {
    uint256 internal constant MAX_UINT256 = 2 ** 256 - 1;

    function mulDivDown(uint256 x, uint256 y, uint256 denominator)
        internal
        pure
        returns (uint256 z)
    {
        /// @solidity memory-safe-assembly
        assembly {
            // Equivalent to require(denominator != 0 && (y == 0 || x <=
            // type(uint256).max / y))
            if iszero(
                mul(denominator, iszero(mul(y, gt(x, div(MAX_UINT256, y)))))
            ) { revert(0, 0) }

            // Divide x * y by the denominator.
            z := div(mul(x, y), denominator)
        }
    }
}

/// @title FraxV3FrxEthAdapter
/// Adapter for frxETH and sfrxETH tokens of FraxV3
/// @dev This contract only supports: ETH -> sfrxETH and frxETH <-> sfrxETH
contract FraxV3FrxEthAdapter is ISwapAdapter {
    using SafeERC20 for IERC20;
    using FixedPointMathLib for uint256;

    uint256 constant PRECISE_UNIT = 1e18;

    IFrxEth immutable frxEth;
    IFrxEthMinter immutable frxEthMinter;
    ISfrxEth immutable sfrxEth;

    constructor(address _frxEthMinter, address _sfrxEth) {
        sfrxEth = ISfrxEth(_sfrxEth);
        frxEth = IFrxEth(address(0x5E8422345238F34275888049021821E8E08CAa1f));

        frxEthMinter = IFrxEthMinter(_frxEthMinter);
    }

    /// @dev check input tokens for allowed trades
    function isSwapNotSupported(address sellToken, address buyToken)
        internal
        view
        returns (bool)
    {
        if (
            (
                sellToken != address(frxEth) && sellToken != address(sfrxEth)
                    && sellToken != address(0)
            ) || (buyToken != address(frxEth) && buyToken != address(sfrxEth))
                || (sellToken == address(0) && buyToken != address(sfrxEth))
                || buyToken == sellToken
        ) {
            return true;
        }
        return false;
    }

    /// @dev enable receive to fill the contract with ether for payable swaps
    receive() external payable {}

    /// @inheritdoc ISwapAdapter
    function price(
        bytes32,
        address sellToken,
        address buyToken,
        uint256[] memory _specifiedAmounts
    ) external view override returns (Fraction[] memory _prices) {
        _prices = new Fraction[](_specifiedAmounts.length);

        if (isSwapNotSupported(sellToken, buyToken)) {
            return _prices;
        }

        for (uint256 i = 0; i < _specifiedAmounts.length; i++) {
            _prices[i] = getPriceAt(sellToken, _specifiedAmounts[i]);
        }
    }

    /// @inheritdoc ISwapAdapter
    /// @notice Executes a swap on the contract.
    /// @param sellToken The token being sold.
    /// @param buyToken The token being bought.
    /// @param side Either buy or sell.
    /// @param specifiedAmount The amount to be traded.
    /// @return trade The amount of tokens being sold or bought.
    function swap(
        bytes32,
        address sellToken,
        address buyToken,
        OrderSide side,
        uint256 specifiedAmount
    ) external override returns (Trade memory trade) {
        trade.price = Fraction(PRECISE_UNIT, PRECISE_UNIT);
        trade.calculatedAmount = 0;
        trade.gasUsed = 0;

        if (isSwapNotSupported(sellToken, buyToken)) {
            return trade;
        }

        uint256 gasBefore = gasleft();

        if (side == OrderSide.Sell) {
            trade.calculatedAmount = sell(sellToken, specifiedAmount);
            trade.calculatedAmount != 0
                ? trade.price = Fraction(trade.calculatedAmount, specifiedAmount)
                : trade.price;
        } else {
            trade.calculatedAmount = buy(sellToken, specifiedAmount);
            trade.calculatedAmount != 0
                ? trade.price = Fraction(specifiedAmount, trade.calculatedAmount)
                : trade.price;
        }

        trade.gasUsed = gasBefore - gasleft();
    }

    /// @inheritdoc ISwapAdapter
    function getLimits(bytes32, address sellToken, address buyToken)
        external
        view
        override
        returns (uint256[] memory limits)
    {
        limits = new uint256[](2);
        limits[0] = 0;
        limits[1] = 0;

        if (isSwapNotSupported(sellToken, buyToken)) {
            return limits;
        }

        if (sellToken == address(frxEth) || sellToken == address(0)) {
            // No limits when minting sfrxEth, the protocol has no limits when
            // creating
            //  new sfrxETH as long as the user holds enough frxETH.
            limits[0] = type(uint128).max;
            limits[1] = type(uint128).max;
        } else if (buyToken == address(frxEth)) {
            uint256 totalAssets = sfrxEth.totalAssets();
            // the amount of sfrxEth a user can exchange for frxETH is limited
            // by the
            //  amount of frxEth owned by the protocol, we convert that into
            // shares to
            //  get the corresponding sfrxEth amount.
            limits[0] = sfrxEth.previewWithdraw(totalAssets);
            // frxETH a user can buy is limited by the contracts balance
            limits[1] = totalAssets;
        }

        return limits;
    }

    /// @inheritdoc ISwapAdapter
    function getCapabilities(bytes32, address, address)
        external
        pure
        override
        returns (Capability[] memory capabilities)
    {
        capabilities = new Capability[](4);
        capabilities[0] = Capability.SellOrder;
        capabilities[1] = Capability.BuyOrder;
        capabilities[2] = Capability.PriceFunction;
        capabilities[3] = Capability.ConstantPrice;
    }

    /// @inheritdoc ISwapAdapter
    function getTokens(bytes32)
        external
        view
        override
        returns (address[] memory tokens)
    {
        tokens = new address[](2);

        tokens[0] = frxEthMinter.frxETHToken();
        tokens[1] = frxEthMinter.sfrxETHToken();
    }

    /// @inheritdoc ISwapAdapter
    /// @dev although FraxV3 frxETH has no pool ids, we return the sFrxETH and
    /// frxETHMinter addresses as pools
    function getPoolIds(uint256, uint256)
        external
        view
        override
        returns (bytes32[] memory ids)
    {
        ids = new bytes32[](2);
        ids[0] = bytes20(address(sfrxEth));
        ids[1] = bytes20(address(frxEthMinter));
    }

    /// @notice Executes a sell order on the contract.
    /// @param sellToken The token being sold.
    /// @param amount The amount to be traded.
    /// @return calculatedAmount The amount of tokens received.
    function sell(address sellToken, uint256 amount)
        internal
        returns (uint256 calculatedAmount)
    {
        if (sellToken == address(0)) {
            return frxEthMinter.submitAndDeposit{value: amount}(msg.sender);
        }

        IERC20(sellToken).safeTransferFrom(msg.sender, address(this), amount);

        if (sellToken == address(sfrxEth)) {
            return sfrxEth.redeem(amount, msg.sender, address(this));
        } else {
            IERC20(sellToken).safeIncreaseAllowance(address(sfrxEth), amount);
            return sfrxEth.deposit(amount, msg.sender);
        }
    }

    /// @notice Executes a buy order on the contract.
    /// @param sellToken The token being sold.
    /// @param amount The amount of buyToken to receive.
    /// @return calculatedAmount The amount of tokens received.
    function buy(address sellToken, uint256 amount)
        internal
        returns (uint256 calculatedAmount)
    {
        if (sellToken == address(0)) {
            uint256 amountIn = sfrxEth.previewMint(amount);
            frxEthMinter.submit{value: amountIn}();
            IERC20(address(frxEth)).safeIncreaseAllowance(
                address(sfrxEth), amountIn
            );
            return sfrxEth.mint(amount, msg.sender);
        }

        if (sellToken == address(sfrxEth)) {
            uint256 amountIn = sfrxEth.previewWithdraw(amount);
            IERC20(sellToken).safeTransferFrom(
                msg.sender, address(this), amountIn
            );
            return sfrxEth.withdraw(amount, msg.sender, address(this));
        } else {
            uint256 amountIn = sfrxEth.previewMint(amount);
            IERC20(sellToken).safeTransferFrom(
                msg.sender, address(this), amountIn
            );
            IERC20(sellToken).safeIncreaseAllowance(address(sfrxEth), amountIn);
            return sfrxEth.mint(amount, msg.sender);
        }
    }

    /// @notice Calculates prices for a specified amount
    /// @dev frxEth is 1:1 eth
    /// @param sellToken the token to sell
    /// @param amountIn The amount of the token being sold.
    /// @return (fraction) price as a fraction corresponding to the provided
    /// amount.
    function getPriceAt(address sellToken, uint256 amountIn)
        internal
        view
        returns (Fraction memory)
    {
        if (sellToken == address(frxEth) || sellToken == address(0)) {
            // calculate price sfrxEth/frxEth
            uint256 totStoredAssets = sfrxEth.totalAssets() + amountIn;
            uint256 newMintedShares = sfrxEth.previewDeposit(amountIn);
            uint256 totMintedShares = sfrxEth.totalSupply() + newMintedShares;
            uint256 numerator =
                PRECISE_UNIT.mulDivDown(totMintedShares, totStoredAssets);
            return Fraction(numerator, PRECISE_UNIT);
        } else {
            // calculate price frxEth/sfrxEth
            uint256 fraxAmountRedeemed = sfrxEth.previewRedeem(amountIn);
            uint256 totStoredAssets = sfrxEth.totalAssets() - fraxAmountRedeemed;
            uint256 totMintedShares = sfrxEth.totalSupply() - amountIn;
            uint256 numerator = totMintedShares == 0
                ? PRECISE_UNIT
                : PRECISE_UNIT.mulDivDown(totStoredAssets, totMintedShares);
            return Fraction(numerator, PRECISE_UNIT);
        }
    }
}

interface IFrxEth {
    function balanceOf(address) external view returns (uint256);

    function totalSupply() external view returns (uint256);

    function minters(address) external view returns (bool);
}

interface ISfrxEth {
    /// @dev even though the balance address of frxETH token is around 223,701
    /// tokens, it returns 0 when the
    /// address of frxEth is passed as an argument
    function balanceOf(address) external view returns (uint256);

    function previewDeposit(uint256 assets) external view returns (uint256);

    function previewMint(uint256 shares) external view returns (uint256);

    function previewRedeem(uint256 shares) external view returns (uint256);

    function previewWithdraw(uint256 assets) external view returns (uint256);

    /// @dev returns the totalSupply of frxETH
    function totalSupply() external view returns (uint256);

    /// @notice Compute the amount of tokens available to share holders
    function totalAssets() external view returns (uint256);

    function asset() external view returns (ERC20);

    function deposit(uint256 assets, address receiver)
        external
        returns (uint256 shares);

    function mint(uint256 shares, address receiver)
        external
        returns (uint256 assets);

    function storedTotalAssets() external view returns (uint256);

    function withdraw(uint256 assets, address receiver, address owner)
        external
        returns (uint256 shares);

    function redeem(uint256 shares, address receiver, address owner)
        external
        returns (uint256 assets);
}

interface IFrxEthMinter {
    //function sfrxETHTokenContract() external view returns (ISfrxEth);

    function sfrxETHToken() external view returns (address);

    function frxETHToken() external view returns (address);

    function currentWithheldETH() external view returns (uint256);

    function DEPOSIT_SIZE() external view returns (uint256);

    /// @notice Mint frxETH to the sender depending on the ETH value sent
    function submit() external payable;

    /// @notice Mint frxETH and deposit it to receive sfrxETH in one transaction
    function submitAndDeposit(address recipient)
        external
        payable
        returns (uint256 shares);
}
