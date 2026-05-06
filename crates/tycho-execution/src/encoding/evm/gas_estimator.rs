use num_bigint::BigUint;

use crate::encoding::models::{Solution, Strategy};

pub(crate) fn estimate_gas_usage(_solution: &Solution, _strategy: Strategy) -> BigUint {
    // loop through solution to see the swaps and if they have estimated_gas_usage assigned
    //   - if not -> skip and do nothing
    //   - if yes ->
    //      - sum up all the swap costs
    //      - add router overhead
    //      - add token transfer costs depend on the swap type. also depend on if fees are being
    //        taken or not
    //         - for single swaps: is it worth to model properly?
    //         - for sequential swaps: is it worth to model properly?
    //         - for split swaps: all transfers need to go through the router
    //      - add total gas usage to EncodedSolution
    BigUint::ZERO
}
