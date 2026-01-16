// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

error FeeTaker__InvalidDataLength();
error FeeTaker__FeeTooHigh();

/**
 * @title FeeTaker
 * @notice Contract responsible for calculating fees on swap outputs
 * @dev This contract is called via staticCall from TychoRouter.
 *      It only calculates fees and returns the values - accounting is done by the caller.
 */
contract FeeTaker {
    uint16 private constant MAX_FEE_BPS = 10000; // 100% max

    /**
     * @notice Calculates fees from the swap output amount
     * @dev Called via delegatecall from TychoRouter. Does not perform any accounting.
     * @param amountIn The amount before fee deduction
     * @param data Encoded fee parameters (46 bytes total):
     *        - solverFeeBps (uint16): Solver fee in basis points
     *        - solverFeeReceiver (address): Address to receive solver fee
     *        - routerFeeOnOutputBps (uint16): Router fee on output in basis points
     *        - routerFeeOnSolverFeeBps (uint16): Router fee on solver fee in basis points
     *        - routerFeeReceiver (address): Address to receive router fees
     * @return amountOut The amount remaining after all fee deductions
     * @return routerFee Total router fee amount
     * @return routerFeeReceiverAddr Address to receive router fees
     * @return solverFee Solver fee amount (after router's cut)
     * @return solverFeeReceiverAddr Address to receive solver fee
     */
    function takeFee(uint256 amountIn, bytes calldata data)
        external
        pure
        returns (
            uint256 amountOut,
            uint256 routerFee,
            address routerFeeReceiverAddr,
            uint256 solverFee,
            address solverFeeReceiverAddr
        )
    {
        (
            uint16 solverFeeBps,
            address solverFeeReceiver,
            uint16 routerFeeOnOutputBps,
            uint16 routerFeeOnSolverFeeBps,
            address routerFeeReceiver
        ) = _decodeFeeData(data);

        if (
            (solverFeeBps + routerFeeOnOutputBps > MAX_FEE_BPS)
                || routerFeeOnSolverFeeBps > MAX_FEE_BPS
        ) {
            revert FeeTaker__FeeTooHigh();
        }

        amountOut = amountIn;
        uint256 routerFeeOnSolverFee = 0;
        uint256 solverPortion = 0;

        // Calculate solver fee if > 0
        if (solverFeeBps > 0) {
            // Save numerator for later routerFeeOnSolverFee calculation to avoid
            // divide-before-multiply precision loss and warning
            uint256 solverFeeNumerator = amountOut * solverFeeBps;
            uint256 totalSolverFee = solverFeeNumerator / 10_000;
            amountOut -= totalSolverFee;

            // Calculate router's cut of the solver fee
            if (routerFeeOnSolverFeeBps > 0) {
                routerFeeOnSolverFee =
                    (solverFeeNumerator * routerFeeOnSolverFeeBps) / 100_000_000;
            }

            // Solver gets their portion (after router's cut)
            solverPortion = totalSolverFee - routerFeeOnSolverFee;
        }

        uint256 totalRouterFee = routerFeeOnSolverFee;

        // Calculate router fee on output amount if > 0
        if (routerFeeOnOutputBps > 0) {
            uint256 routerFeeOnOutput =
                (amountOut * routerFeeOnOutputBps) / 10000;
            amountOut -= routerFeeOnOutput;
            totalRouterFee += routerFeeOnOutput;
        }

        return (
            amountOut,
            totalRouterFee,
            routerFeeReceiver,
            solverPortion,
            solverFeeReceiver
        );
    }

    /**
     * @notice Decodes the fee data parameters
     * @param data Encoded fee parameters
     * @return solverFeeBps Solver fee in basis points
     * @return solverFeeReceiver Address to receive solver fee
     * @return routerFeeOnOutputBps Router fee on output in basis points
     * @return routerFeeOnSolverFeeBps Router fee on solver fee in basis points
     * @return routerFeeReceiver Address to receive router fees
     */
    function _decodeFeeData(bytes calldata data)
        internal
        pure
        returns (
            uint16 solverFeeBps,
            address solverFeeReceiver,
            uint16 routerFeeOnOutputBps,
            uint16 routerFeeOnSolverFeeBps,
            address routerFeeReceiver
        )
    {
        if (data.length != 46) {
            revert FeeTaker__InvalidDataLength();
        }

        solverFeeBps = uint16(bytes2(data[0:2]));
        solverFeeReceiver = address(bytes20(data[2:22]));
        routerFeeOnOutputBps = uint16(bytes2(data[22:24]));
        routerFeeOnSolverFeeBps = uint16(bytes2(data[24:26]));
        routerFeeReceiver = address(bytes20(data[26:46]));
    }
}
