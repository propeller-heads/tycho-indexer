// SPDX-License-Identifier: AGPL-3.0-or-later
pragma experimental ABIEncoderV2;
pragma solidity ^0.8.13;

import {IERC20, ISwapAdapter} from "src/interfaces/ISwapAdapter.sol";

/// @title Etherfi Adapter
/// @dev This contract supports the following swaps: eETH<->ETH, wETH<->eETH, wETH<->ETH
contract EtherfiAdapter is ISwapAdapter {

    IWeEth wEeth;
    IeEth eEth;
    ILiquidityPool liquidityPool;

    constructor(address _wEeth) {
        wEeth = IWeEth(_wEeth);
        eEth = wEeth.eETH();
        liquidityPool = eEth.liquidityPool();
    }

    /// @dev Check if tokens in input are supported by this adapter
    modifier checkInputTokens(address sellToken, address buyToken) {
        if(sellToken == buyToken) {
            revert Unavailable("This pool only supports eETH, weEth and ETH");
        }
        if(sellToken != address(wEeth) && sellToken != address(eEth) && sellToken && sellToken != address(0)) {
            revert Unavailable("This pool only supports eETH, weEth and ETH");
        }
        if(buyToken != address(wEeth) && buyToken != address(eEth) && buyToken != address(0)) {
            revert Unavailable("This pool only supports eETH, weEth and ETH");
        }
        _;
    }

    function price(
        bytes32 _poolId,
        IERC20 _sellToken,
        IERC20 _buyToken,
        uint256[] memory _specifiedAmounts
    ) external view override returns (Fraction[] memory _prices) {
        revert NotImplemented("TemplateSwapAdapter.price");
    }

    function swap(
        bytes32 poolId,
        IERC20 sellToken,
        IERC20 buyToken,
        OrderSide side,
        uint256 specifiedAmount
    ) external returns (Trade memory trade) {
        revert NotImplemented("TemplateSwapAdapter.swap");
    }

    function getLimits(bytes32 poolId, IERC20 sellToken, IERC20 buyToken)
        external
        returns (uint256[] memory limits)
    {
        revert NotImplemented("TemplateSwapAdapter.getLimits");
    }

    function getCapabilities(bytes32 poolId, IERC20 sellToken, IERC20 buyToken)
        external
        returns (Capability[] memory capabilities)
    {
        revert NotImplemented("TemplateSwapAdapter.getCapabilities");
    }

    /// @inheritdoc ISwapAdapter
    function getTokens(bytes32)
        external
        view
        override
        returns (IERC20[] memory tokens)
    {
        tokens = new IERC20[](3);
        tokens[0] = IERC20(address(0));
        tokens[1] = IERC20(address(eEth));
        tokens[2] = IERC20(address(wEeth));
    }

    /// @inheritdoc ISwapAdapter
    function getPoolIds(uint256, uint256)
        external
        returns (bytes32[] memory ids)
    {
        ids[] = new bytes32[](1);
        ids[0] = bytes20(address(liquidityPool));
    }
}

interface ILiquidityPool {

    function numPendingDeposits() external view returns (uint32);
    function totalValueOutOfLp() external view returns (uint128);
    function totalValueInLp() external view returns (uint128);
    function getTotalEtherClaimOf(address _user) external view returns (uint256);
    function getTotalPooledEther() external view returns (uint256);
    function sharesForAmount(uint256 _amount) external view returns (uint256);
    function sharesForWithdrawalAmount(uint256 _amount) external view returns (uint256);
    function amountForShare(uint256 _share) external view returns (uint256);

    function deposit() external payable returns (uint256);
    function deposit(address _referral) external payable returns (uint256);
    function deposit(address _user, address _referral) external payable returns (uint256);

}

interface IeEth {

    function liquidityPool() external view returns (ILiquidityPool);

    function totalShares() external view returns (uint256);

    function shares(address _user) external view returns (uint256);

}

interface IWeEth {

    function eETH() external view returns (IeEth);

    function getWeETHByeETH(uint256 _eETHAmount) external view returns (uint256);

    function getEETHByWeETH(uint256 _weETHAmount) external view returns (uint256);

    function wrap(uint256 _eETHAmount) external returns (uint256);

    function unwrap(uint256 _weETHAmount) external returns (uint256);

}
