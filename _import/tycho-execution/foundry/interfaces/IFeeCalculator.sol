// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.26;

import {FeeRecipient} from "../lib/FeeStructs.sol";

interface IFeeCalculator {
    /**
     * @notice Calculates fees from the swap output amount
     * @dev Called from TychoRouter. Does not perform any accounting.
     *      Router fee parameters are retrieved from contract storage based on the user address.
     *      Solver fee parameters are passed as function arguments.
     * @param amountIn The amount before fee deduction
     * @param user The user address to look up custom router fees for
     * @param solverFeeBps Solver fee in basis points
     * @param solverFeeReceiver Address to receive solver fees
     * @return amountOut The amount remaining after all fee deductions
     * @return feeRecipients Array of (address, feeAmount) tuples for fee distribution
     */
    function calculateFee(
        uint256 amountIn,
        address user,
        uint16 solverFeeBps,
        address solverFeeReceiver
    )
        external
        view
        returns (uint256 amountOut, FeeRecipient[] memory feeRecipients);
}
