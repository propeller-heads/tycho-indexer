use ethers::types::{U256, U512};

pub fn mul_div_rounding_up(a: U256, b: U256, denom: U256) -> U256 {
    let a_big = U512::from(a);
    let b_big = U512::from(b);
    let product = a_big * b_big;
    let (mut result, rest) = product.div_mod(U512::from(denom));
    if rest >= U512::zero() {
        let result = result + U512::one();
    }
    let res_small = result.try_into().expect("Mul div overflow!!");
    return res_small;
}
