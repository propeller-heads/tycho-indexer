#![allow(dead_code)]

use alloy::primitives::Address;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HookOptions {
    AfterRemoveLiquidityReturnsDelta = 0,
    AfterAddLiquidityReturnsDelta = 1,
    AfterSwapReturnsDelta = 2,
    BeforeSwapReturnsDelta = 3,
    AfterDonate = 4,
    BeforeDonate = 5,
    AfterSwap = 6,
    BeforeSwap = 7,
    AfterRemoveLiquidity = 8,
    BeforeRemoveLiquidity = 9,
    AfterAddLiquidity = 10,
    BeforeAddLiquidity = 11,
    AfterInitialize = 12,
    BeforeInitialize = 13,
}

// from https://github.com/shuhuiluo/uniswap-v4-sdk-rs/blob/main/src/utils/hook.rs#L69
pub const fn has_permission(address: Address, hook_option: HookOptions) -> bool {
    let mask = ((address.0 .0[18] as u64) << 8) | (address.0 .0[19] as u64);
    let hook_flag_index = hook_option as u64;
    mask & (1 << hook_flag_index) != 0
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use alloy::primitives::U160;

    use super::*;

    fn construct_hook_address(hook_options: Vec<HookOptions>) -> Address {
        let mut hook_flags = U160::ZERO;
        let one = U160::from_limbs([1, 0, 0]);
        for hook_option in hook_options {
            hook_flags |= one << (hook_option as u8);
        }
        Address::from(hook_flags)
    }

    const EMPTY_HOOK_ADDRESS: Address = Address::ZERO;
    static HOOK_BEFORE_INITIALIZE: LazyLock<Address> =
        LazyLock::new(|| construct_hook_address(vec![HookOptions::BeforeInitialize]));
    static HOOK_AFTER_INITIALIZE: LazyLock<Address> =
        LazyLock::new(|| construct_hook_address(vec![HookOptions::AfterInitialize]));
    static HOOK_BEFORE_ADD_LIQUIDITY: LazyLock<Address> =
        LazyLock::new(|| construct_hook_address(vec![HookOptions::BeforeAddLiquidity]));
    static HOOK_AFTER_ADD_LIQUIDITY: LazyLock<Address> =
        LazyLock::new(|| construct_hook_address(vec![HookOptions::AfterAddLiquidity]));
    static HOOK_BEFORE_REMOVE_LIQUIDITY: LazyLock<Address> =
        LazyLock::new(|| construct_hook_address(vec![HookOptions::BeforeRemoveLiquidity]));
    static HOOK_AFTER_REMOVE_LIQUIDITY: LazyLock<Address> =
        LazyLock::new(|| construct_hook_address(vec![HookOptions::AfterRemoveLiquidity]));
    static HOOK_BEFORE_SWAP: LazyLock<Address> =
        LazyLock::new(|| construct_hook_address(vec![HookOptions::BeforeSwap]));
    static HOOK_AFTER_SWAP: LazyLock<Address> =
        LazyLock::new(|| construct_hook_address(vec![HookOptions::AfterSwap]));
    static HOOK_BEFORE_DONATE: LazyLock<Address> =
        LazyLock::new(|| construct_hook_address(vec![HookOptions::BeforeDonate]));
    static HOOK_AFTER_DONATE: LazyLock<Address> =
        LazyLock::new(|| construct_hook_address(vec![HookOptions::AfterDonate]));
    static HOOK_BEFORE_SWAP_RETURNS_DELTA: LazyLock<Address> =
        LazyLock::new(|| construct_hook_address(vec![HookOptions::BeforeSwapReturnsDelta]));
    static HOOK_AFTER_SWAP_RETURNS_DELTA: LazyLock<Address> =
        LazyLock::new(|| construct_hook_address(vec![HookOptions::AfterSwapReturnsDelta]));
    static HOOK_AFTER_ADD_LIQUIDITY_RETURNS_DELTA: LazyLock<Address> =
        LazyLock::new(|| construct_hook_address(vec![HookOptions::AfterAddLiquidityReturnsDelta]));
    static HOOK_AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA: LazyLock<Address> = LazyLock::new(|| {
        construct_hook_address(vec![HookOptions::AfterRemoveLiquidityReturnsDelta])
    });

    mod has_permission {
        use super::*;

        #[test]
        fn before_initialize() {
            assert!(has_permission(*HOOK_BEFORE_INITIALIZE, HookOptions::BeforeInitialize));
            assert!(!has_permission(EMPTY_HOOK_ADDRESS, HookOptions::BeforeInitialize));
        }

        #[test]
        fn after_initialize() {
            assert!(has_permission(*HOOK_AFTER_INITIALIZE, HookOptions::AfterInitialize));
            assert!(!has_permission(EMPTY_HOOK_ADDRESS, HookOptions::AfterInitialize));
        }

        #[test]
        fn before_add_liquidity() {
            assert!(has_permission(*HOOK_BEFORE_ADD_LIQUIDITY, HookOptions::BeforeAddLiquidity));
            assert!(!has_permission(EMPTY_HOOK_ADDRESS, HookOptions::BeforeAddLiquidity));
        }

        #[test]
        fn after_add_liquidity() {
            assert!(has_permission(*HOOK_AFTER_ADD_LIQUIDITY, HookOptions::AfterAddLiquidity));
            assert!(!has_permission(EMPTY_HOOK_ADDRESS, HookOptions::AfterAddLiquidity));
        }

        #[test]
        fn before_remove_liquidity() {
            assert!(has_permission(
                *HOOK_BEFORE_REMOVE_LIQUIDITY,
                HookOptions::BeforeRemoveLiquidity
            ));
            assert!(!has_permission(EMPTY_HOOK_ADDRESS, HookOptions::BeforeRemoveLiquidity));
        }

        #[test]
        fn after_remove_liquidity() {
            assert!(has_permission(
                *HOOK_AFTER_REMOVE_LIQUIDITY,
                HookOptions::AfterRemoveLiquidity
            ));
            assert!(!has_permission(EMPTY_HOOK_ADDRESS, HookOptions::AfterRemoveLiquidity));
        }

        #[test]
        fn before_swap() {
            assert!(has_permission(*HOOK_BEFORE_SWAP, HookOptions::BeforeSwap));
            assert!(!has_permission(EMPTY_HOOK_ADDRESS, HookOptions::BeforeSwap));
        }

        #[test]
        fn after_swap() {
            assert!(has_permission(*HOOK_AFTER_SWAP, HookOptions::AfterSwap));
            assert!(!has_permission(EMPTY_HOOK_ADDRESS, HookOptions::AfterSwap));
        }

        #[test]
        fn before_donate() {
            assert!(has_permission(*HOOK_BEFORE_DONATE, HookOptions::BeforeDonate));
            assert!(!has_permission(EMPTY_HOOK_ADDRESS, HookOptions::BeforeDonate));
        }

        #[test]
        fn after_donate() {
            assert!(has_permission(*HOOK_AFTER_DONATE, HookOptions::AfterDonate));
            assert!(!has_permission(EMPTY_HOOK_ADDRESS, HookOptions::AfterDonate));
        }

        #[test]
        fn before_swap_returns_delta() {
            assert!(has_permission(
                *HOOK_BEFORE_SWAP_RETURNS_DELTA,
                HookOptions::BeforeSwapReturnsDelta
            ));
            assert!(!has_permission(EMPTY_HOOK_ADDRESS, HookOptions::BeforeSwapReturnsDelta));
        }

        #[test]
        fn after_swap_returns_delta() {
            assert!(has_permission(
                *HOOK_AFTER_SWAP_RETURNS_DELTA,
                HookOptions::AfterSwapReturnsDelta
            ));
            assert!(!has_permission(EMPTY_HOOK_ADDRESS, HookOptions::AfterSwapReturnsDelta));
        }

        #[test]
        fn after_add_liquidity_returns_delta() {
            assert!(has_permission(
                *HOOK_AFTER_ADD_LIQUIDITY_RETURNS_DELTA,
                HookOptions::AfterAddLiquidityReturnsDelta
            ));
            assert!(!has_permission(
                EMPTY_HOOK_ADDRESS,
                HookOptions::AfterAddLiquidityReturnsDelta
            ));
        }

        #[test]
        fn after_remove_liquidity_returns_delta() {
            assert!(has_permission(
                *HOOK_AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA,
                HookOptions::AfterRemoveLiquidityReturnsDelta
            ));
            assert!(!has_permission(
                EMPTY_HOOK_ADDRESS,
                HookOptions::AfterRemoveLiquidityReturnsDelta
            ));
        }
    }
}
