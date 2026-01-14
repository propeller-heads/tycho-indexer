// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/Address.sol";

error FeeTaker__InvalidDataLength();
error FeeTaker__FeeTooHigh();

/**
 * @title FeeTaker
 * @notice Contract responsible for calculating and deducting fees from swap outputs
 * @dev This contract is called via delegatecall from TychoRouter, giving it access
 *      to the router's storage
 */
contract FeeTaker {
    using SafeERC20 for IERC20;
    uint16 private constant MAX_FEE_BPS = 10000; // 100% max

    /**
     * @notice Calculates and deducts fees from the swap output amount and updates
     *         the vault balances of the fee receivers
     * @dev Called via delegatecall from TychoRouter
     * @param amountIn The amount before fee deduction
     * @param data Encoded fee parameters:
     *        - solverFeeBps (uint16): Solver fee in basis points
     *        - solverFeeReceiver (address): Address to receive solver fee
     *        - routerFeeOnOutputBps (uint16): Router fee on output in basis points
     *        - routerFeeOnSolverFeeBps (uint16): Router fee on solver fee in basis points
     *        - routerFeeReceiver (address): Address to receive router fees
     *        - token (address): The token address (address(0) for native ETH)
     * @return amountOut The amount remaining after all fee deductions
     */
    function takeFee(uint256 amountIn, bytes calldata data)
        external
        returns (uint256 amountOut)
    {
        (
            uint16 solverFeeBps,
            address solverFeeReceiver,
            uint16 routerFeeOnOutputBps,
            uint16 routerFeeOnSolverFeeBps,
            address routerFeeReceiver,
            address token
        ) = _decodeFeeData(data);

        if (
            solverFeeBps > MAX_FEE_BPS || routerFeeOnOutputBps > MAX_FEE_BPS
                || routerFeeOnSolverFeeBps > MAX_FEE_BPS
        ) {
            revert FeeTaker__FeeTooHigh();
        }

        amountOut = amountIn;
        uint256 solverFee = 0;

        // Deduct solution fee if > 0
        if (solverFeeBps > 0) {
            solverFee = (amountOut * solverFeeBps) / 10000;
            amountOut -= solverFee;
            // TODO uncomment when implemented
            //  _updateDeltaAccounting(token, -int256(solverFee));
            //  _creditVault(solverFeeReceiver, token, solverFee);
        }

        uint256 totalRouterFeesTaken = 0;
        // Deduct router fee on output amount if > 0
        if (routerFeeOnOutputBps > 0) {
            uint256 routerFeeOnOutput =
                (amountOut * routerFeeOnOutputBps) / 10000;
            amountOut -= routerFeeOnOutput;
            totalRouterFeesTaken += routerFeeOnOutput;
        }

        // Deduct router fee on solver fee if > 0 (calculated from solution fee)
        if (routerFeeOnSolverFeeBps > 0 && solverFee > 0) {
            uint256 routerFeeOnSolverFee =
                (solverFee * routerFeeOnSolverFeeBps) / 10000;
            amountOut -= routerFeeOnSolverFee;
            totalRouterFeesTaken += routerFeeOnSolverFee;
        }

        if (totalRouterFeesTaken > 0) {
            // TODO uncomment when implemented
            //  _updateDeltaAccounting(token, -int256(totalRouterFeesTaken));
            //  _creditVault(routerFeeReceiver, token, totalRouterFeesTaken);
        }

        return amountOut;
    }

    /**
     * @notice Decodes the fee data parameters
     * @param data Encoded fee parameters
     * @return solverFeeBps Solver fee in basis points
     * @return solverFeeReceiver Address to receive solver fee
     * @return routerFeeOnOutputBps Router fee on output in basis points
     * @return routerFeeOnSolverFeeBps Router fee on solver fee in basis points
     * @return routerFeeReceiver Address to receive router fees
     * @return token The token address
     */
    function _decodeFeeData(bytes calldata data)
        internal
        pure
        returns (
            uint16 solverFeeBps,
            address solverFeeReceiver,
            uint16 routerFeeOnOutputBps,
            uint16 routerFeeOnSolverFeeBps,
            address routerFeeReceiver,
            address token
        )
    {
        if (data.length != 66) {
            revert FeeTaker__InvalidDataLength();
        }

        solverFeeBps = uint16(bytes2(data[0:2]));
        solverFeeReceiver = address(bytes20(data[2:22]));
        routerFeeOnOutputBps = uint16(bytes2(data[22:24]));
        routerFeeOnSolverFeeBps = uint16(bytes2(data[24:26]));
        routerFeeReceiver = address(bytes20(data[26:46]));
        token = address(bytes20(data[46:66]));
    }
}
