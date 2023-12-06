// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import "src/interfaces/ISwapAdapterTypes.sol";

library FractionMath {
    /// @dev Compares two Fraction instances from ISwapAdapterTypes.
    /// @param frac1 The first Fraction instance.
    /// @param frac2 The second Fraction instance.
    /// @return int8 Returns 0 if fractions are equal, 1 if frac1 is greater, -1
    /// if frac1 is lesser.
    function compareFractions(
        ISwapAdapterTypes.Fraction memory frac1,
        ISwapAdapterTypes.Fraction memory frac2
    ) internal pure returns (int8) {
        uint256 crossProduct1 = frac1.numerator * frac2.denominator;
        uint256 crossProduct2 = frac2.numerator * frac1.denominator;

        // fractions are equal
        if (crossProduct1 == crossProduct2) return 0;
        // frac1 is greater than frac2
        else if (crossProduct1 > crossProduct2) return 1;
        // frac1 is less than frac2
        else return -1;
    }
}
