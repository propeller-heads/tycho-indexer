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
        uint256 fixed1 = toQ128x128(frac1.numerator, frac1.denominator);
        uint256 fixed2 = toQ128x128(frac2.numerator, frac2.denominator);

        // fractions are equal
        if (fixed1 == fixed2) return 0;
        // frac1 is greater than frac2
        else if (fixed1 > fixed2) return 1;
        // frac1 is less than frac2
        else return -1;
    }

    /// @notice Converts a Fraction into unsigned Q128.128 fixed point
    function toQ128x128(ISwapAdapterTypes.Fraction memory rational)
        internal
        pure
        returns (uint256 result)
    {
        return toQ128x128(rational.numerator, rational.denominator);
    }

    /// @notice Converts an unsigned rational `numerator / denominator`
    ///         into Q128.128 (unsigned 128.128 fixed point),
    ///         rounding toward zero (floor for positive inputs).
    ///
    ///         see https://github.com/Liquidity-Party/toQ128x128
    ///
    /// @dev Reverts if:
    ///      - `denominator == 0`, or
    ///      - the exact result >= 2^256 (i.e. overflow of uint256).
    ///
    ///      This computes floor(numerator * 2^128 / denominator)
    ///      using a full 512-bit intermediate to avoid precision loss.
    ///
    function toQ128x128(uint256 numerator, uint256 denominator)
        internal
        pure
        returns (uint256 result)
    {
        require(denominator != 0, "toQ128x128: div by zero");

        // We want (numerator * 2^128) / denominator using full precision,
        // so we implement a 512-bit muldiv.
        //
        // Let:
        //   prod = numerator * 2^128
        //
        // Since 2^128 is a power of two, the 512-bit product is easy:
        //   prod0 = (numerator << 128) mod 2^256  (low 256 bits)
        //   prod1 = (numerator >> 128)            (high 256 bits)
        //
        // So prod = (prod1 * 2^256 + prod0).
        uint256 prod0;
        uint256 prod1;
        unchecked {
            prod0 = numerator << 128;
            prod1 = numerator >> 128;
        }

        // If the high 256 bits are zero, the product fits in 256 bits.
        // This is the cheap path: just do a normal 256-bit division.
        if (prod1 == 0) {
            unchecked {
                // denominator was already checked for 0.
                return prod0 / denominator;
            }
        }

        // At this point prod1 > 0, so the 512-bit product does not fit in a
        // uint256. We need a full-precision 512/256 division:
        //
        //   result = floor((prod1 * 2^256 + prod0) / denominator)
        //
        // and we must ensure the final result fits in uint256.

        // Ensure result < 2^256. This is equivalent to requiring:
        //   denominator > prod1
        // because if denominator <= prod1, then:
        //   (prod1 * 2^256) / denominator >= 2^256.
        require(denominator > prod1, "Q128x128: overflow");

        // Make division exact by subtracting the remainder from [prod1 prod0].
        uint256 remainder;
        assembly {
            // remainder = (prod1 * 2^256 + prod0) % denominator
            // Since we can only directly mod 256-bit values, we first mod
            // `prod0`, then adjust using the high word.
            remainder := mulmod(numerator, shl(128, 1), denominator)
        }

        // Now subtract `remainder` from the 512-bit product [prod1 prod0].
        assembly {
            // Subtract remainder from the low part; if it underflows, borrow
            // 1 from the high part.
            let borrow := lt(prod0, remainder)
            prod0 := sub(prod0, remainder)
            prod1 := sub(prod1, borrow)
        }

        // Factor powers of two out of denominator to simplify the division.
        //
        // Let denominator = d * 2^shift, with d odd.
        // We can divide prod0 by 2^shift cheaply (bit shift),
        // then do an exact division by the odd d using modular inverse.
        uint256 twos;
        unchecked {
            // largest power of two divisor of denominator
            twos = denominator & (~denominator + 1);
        }

        assembly {
            // Divide denominator by twos.
            denominator := div(denominator, twos)

            // Divide the low word by twos.
            prod0 := div(prod0, twos)

            // Adjust the high word so that the full 512-bit number is shifted
            // by `twos`.
            // twos = 2^k, so:
            //   combined = prod1 * 2^256 + prod0
            //   combined / twos =
            //     prod1 * 2^256 / twos + prod0 / twos
            // and 2^256 / twos = 2^(256-k).
            //
            // Here we compute:
            //   twos = 2^256 / twos
            twos := add(div(sub(0, twos), twos), 1)

            // Now add the shifted high bits into prod0:
            prod0 := or(prod0, mul(prod1, twos))
        }

        // At this point, denominator is odd and the 512-bit value
        // has been squeezed into prod0 (prod1 is effectively 0).

        // Compute the modular inverse of denominator modulo 2^256.
        // This uses Newton-Raphson iteration:
        //
        //   inv ≡ denominator^{-1} (mod 2^256)
        //
        // Starting from a seed for odd denominator:
        // All operations must be unchecked as they rely on modular arithmetic.
        unchecked {
            uint256 inv = (3 * denominator) ^ 2;

            // Perform Newton-Raphson iterations to refine the inverse.
            // Starting from inv which is correct modulo 2^4, then each
            // Newton-Raphson step doubles the number of correct bits:
            // 2⁴ → 2⁸ → 2¹⁶ → 2³² → 2⁶⁴ →
            // 2¹²⁸ → 2²⁵⁶
            // Requiring six iterations for 256-bit precision:
            inv *= 2 - denominator * inv;
            inv *= 2 - denominator * inv;
            inv *= 2 - denominator * inv;
            inv *= 2 - denominator * inv;
            inv *= 2 - denominator * inv;
            inv *= 2 - denominator * inv;

            // Now inv is the modular inverse of denominator mod 2^256.
            // The exact division result is then:
            //
            //   result = (prod0 * inv) mod 2^256
            //
            // which is just ordinary 256-bit multiplication.
            result = prod0 * inv;
        }
    }
}
