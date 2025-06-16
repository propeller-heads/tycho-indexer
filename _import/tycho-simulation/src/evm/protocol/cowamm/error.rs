

#[derive(Error, Debug)]
pub enum BalancerError {
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
}