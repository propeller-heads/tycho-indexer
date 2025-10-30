//! LP fee library for Uniswap V4
//!
//! This module provides constants and utilities for handling LP fees in Uniswap V4 pools,
//! including special flag bits for dynamic fees and fee overrides.
//!
//! See: <https://github.com/Uniswap/v4-core/blob/main/src/libraries/LPFeeLibrary.sol>

/// Maximum LP fee in pips (1,000,000 = 100%)
pub const MAX_LP_FEE: u32 = 1_000_000;

/// Override flag (bit 22) - signals that the hook wants to override the stored LP fee
#[allow(dead_code)]
pub const OVERRIDE_FEE_FLAG: u32 = 0x400000;

/// Mask to remove the override flag
pub const REMOVE_OVERRIDE_MASK: u32 = 0xBFFFFF;

#[allow(dead_code)]
/// Dynamic fee flag (bit 23) - signals a dynamic fee pool
pub const DYNAMIC_FEE_FLAG: u32 = 0x800000;

/// Removes the override flag from a fee value
///
/// The second bit (bit 22) of the fee returned by beforeSwap is used to signal
/// if the stored LP fee should be overridden in this swap. This function clears
/// that bit to get the actual fee value.
#[inline]
pub fn remove_override_flag(fee: u32) -> u32 {
    fee & REMOVE_OVERRIDE_MASK
}

/// Validates that a fee doesn't exceed MAX_LP_FEE
///
/// Returns `true` if the fee is valid (≤ 1,000,000 pips / 100%)
#[inline]
pub fn is_valid(fee: u32) -> bool {
    fee <= MAX_LP_FEE
}

/// Checks if a fee value is the dynamic fee flag
///
/// Dynamic fee pools are initialized with this special flag value and use hooks
/// to determine fees at swap time.
#[inline]
#[allow(dead_code)]
pub fn is_dynamic_fee(fee: u32) -> bool {
    fee == DYNAMIC_FEE_FLAG
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests inspired by https://github.com/Uniswap/v4-core/blob/main/test/libraries/LPFeeLibrary.t.sol

    #[test]
    fn test_remove_override_flag_with_flag_set() {
        // Test removing override flag when it's set
        let fee_with_flag = 3000u32 | OVERRIDE_FEE_FLAG;
        let cleaned = remove_override_flag(fee_with_flag);
        assert_eq!(cleaned, 3000u32);
    }

    #[test]
    fn test_remove_override_flag_without_flag() {
        // Test removing override flag when it's not set (should be no-op)
        let fee = 3000u32;
        let cleaned = remove_override_flag(fee);
        assert_eq!(cleaned, 3000u32);
    }

    #[test]
    fn test_remove_override_flag_with_dynamic_flag() {
        // Dynamic fee flag (0x800000) should not be affected by override flag removal
        let dynamic_fee = DYNAMIC_FEE_FLAG;
        let cleaned = remove_override_flag(dynamic_fee);
        assert_eq!(cleaned, DYNAMIC_FEE_FLAG);
    }

    #[test]
    fn test_is_valid_zero_fee() {
        assert!(is_valid(0));
    }

    #[test]
    fn test_is_valid_mid_range_fee() {
        // 50% fee (500,000 pips)
        assert!(is_valid(500_000));
    }

    #[test]
    fn test_is_valid_max_fee() {
        // Maximum allowed fee (100% = 1,000,000 pips)
        assert!(is_valid(MAX_LP_FEE));
    }

    #[test]
    fn test_is_valid_exceeds_max() {
        // Fee exceeding maximum should be invalid
        assert!(!is_valid(MAX_LP_FEE + 1));
        assert!(!is_valid(2_000_000));
    }

    #[test]
    fn test_is_dynamic_fee_true() {
        assert!(is_dynamic_fee(DYNAMIC_FEE_FLAG));
    }

    #[test]
    fn test_is_dynamic_fee_false_for_static_fees() {
        assert!(!is_dynamic_fee(0));
        assert!(!is_dynamic_fee(3000));
        assert!(!is_dynamic_fee(MAX_LP_FEE));
    }

    #[test]
    fn test_is_dynamic_fee_false_for_near_values() {
        // Off-by-one values should not be considered dynamic
        assert!(!is_dynamic_fee(DYNAMIC_FEE_FLAG - 1));
        assert!(!is_dynamic_fee(DYNAMIC_FEE_FLAG + 1));
    }

    #[test]
    fn test_constants_match_uniswap() {
        // Verify our constants match Uniswap V4's values
        assert_eq!(MAX_LP_FEE, 1_000_000);
        assert_eq!(OVERRIDE_FEE_FLAG, 0x400000);
        assert_eq!(REMOVE_OVERRIDE_MASK, 0xBFFFFF);
        assert_eq!(DYNAMIC_FEE_FLAG, 0x800000);
    }

    #[test]
    fn test_override_flag_bit_position() {
        // Verify the override flag is at bit 22 (0x400000 = 2^22)
        assert_eq!(OVERRIDE_FEE_FLAG, 1u32 << 22);
    }

    #[test]
    fn test_dynamic_fee_flag_bit_position() {
        // Verify the dynamic fee flag is at bit 23 (0x800000 = 2^23)
        assert_eq!(DYNAMIC_FEE_FLAG, 1u32 << 23);
    }

    #[test]
    fn test_combined_flags() {
        // Test fee with both override and dynamic flags
        let fee_with_both_flags = OVERRIDE_FEE_FLAG | DYNAMIC_FEE_FLAG;
        let cleaned = remove_override_flag(fee_with_both_flags);
        // Should only remove override flag, leaving dynamic flag
        assert_eq!(cleaned, DYNAMIC_FEE_FLAG);
    }

    #[test]
    fn test_real_world_fee_with_override() {
        // Test realistic fee scenario: 0.3% (3000 pips) with override flag
        let fee = 3000u32;
        let fee_with_override = fee | OVERRIDE_FEE_FLAG;

        // Verify the override flag is set
        assert_eq!(fee_with_override, 4_197_304); // 3000 + 0x400000

        // Verify cleaning restores original fee
        let cleaned = remove_override_flag(fee_with_override);
        assert_eq!(cleaned, fee);
        assert!(is_valid(cleaned));
    }
}
