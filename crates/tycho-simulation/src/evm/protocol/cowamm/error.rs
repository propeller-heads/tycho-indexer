use thiserror::Error;

#[derive(Error, Debug)]
pub enum CowAMMError {
    #[error("Token in does not exist")]
    TokenInDoesNotExist,
    #[error("Token out does not exist")]
    TokenOutDoesNotExist,
    #[error("Division by zero")]
    DivZero,
    #[error("Error during division")]
    DivInternal,
    #[error("Addition overflow")]
    AddOverflow,
    #[error("Subtraction underflow")]
    SubUnderflow,
    #[error("Multiplication overflow")]
    MulOverflow,
    #[error("Invalid pool ratio")]
    InvalidPoolRatio,
    #[error("Invalid token amount in")]
    InvalidTokenAmountIn,
    #[error("Token amount in above max")]
    TokenAmountInAboveMax,
    #[error("Invalid token amount out")]
    InvalidTokenAmountOut,
    #[error("Token amount out below min")]
    TokenAmountOutBelowMinAmountOut,
}
