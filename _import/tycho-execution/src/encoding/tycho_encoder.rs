use crate::encoding::{
    errors::EncodingError,
    models::{EncodedSolution, Solution, Transaction},
};

/// A high-level interface for encoding solutions into Tycho-compatible transactions or raw call
/// data.
///
/// This trait is designed to abstract the encoding logic required to prepare swap transactions for
/// the Tycho Router. It enables modular and customizable construction of transactions, allowing
/// integrators to maintain full control over the execution constraints.
///
/// # User Responsibility
///
/// While this trait provides convenience methods, it is **strongly recommended** that users favor
/// [`encode_solutions`] over [`encode_calldata`]. This is because:
///
/// - `encode_solutions` returns raw [`EncodedSolution`] objects, which include Tycho’s swap path
///   encoding, but leave **function argument encoding entirely in the user’s hands**.
/// - The function arguments to the router (e.g., `minAmountOut`, `receiver`, `unwrap`, `permit2`,
///   etc.) are used as **guardrails** to ensure safe on-chain execution.
/// - Automatically constructing full transactions via [`encode_calldata`] can obscure these
///   important safeguards and may result in unexpected behavior or vulnerability to MEV.
///
/// Tycho is only responsible for generating the internal swap plan. **The user must encode the
/// outer function call arguments themselves** and verify that they enforce correct and secure
/// behavior.
pub trait TychoEncoder {
    /// Encodes a list of [`Solution`]s into [`EncodedSolution`]s, which include the function
    /// signature and internal swap call data.
    ///
    /// This method gives users maximum flexibility and control. It **does not** produce full
    /// transaction objects. Users are responsible for:
    /// - Constructing the full calldata using their own encoding logic.
    /// - Managing execution-critical parameters like `minAmountOut`.
    ///
    /// # Returns
    /// A vector of encoded solutions, each containing:
    /// - The Tycho method function signature
    /// - The encoded swap path
    /// - Additional metadata (e.g., permit2 information)
    ///
    /// # Recommendation
    /// Use this method if you care about execution safety and want to avoid surprises.
    fn encode_solutions(
        &self,
        solutions: Vec<Solution>,
    ) -> Result<Vec<EncodedSolution>, EncodingError>;

    /// Encodes a list of [`Solution`]s directly into executable transactions for the Tycho router.
    ///
    /// This method wraps around Tycho’s example encoding logic (see [`encode_tycho_router_call`])
    /// and should only be used for **prototyping or development**.
    ///
    /// # Warning
    /// This implementation uses default logic to construct the outer calldata (e.g., for setting
    /// `minAmountOut`). This might not be optimal or safe for production use.
    ///
    /// To ensure correctness, **users should implement their own encoding pipeline** using
    /// [`encode_solutions`].
    ///
    /// # Returns
    /// A vector of fully constructed [`Transaction`]s that can be submitted to a node or bundler.
    #[deprecated(note = "Please use `encode_solutions` instead")]
    fn encode_full_calldata(
        &self,
        solutions: Vec<Solution>,
    ) -> Result<Vec<Transaction>, EncodingError>;

    /// Performs solution-level validation and sanity checks.
    ///
    /// This function can be used to verify whether a proposed solution is structurally sound and
    /// ready for encoding.
    ///
    /// # Returns
    /// - `Ok(())` if the solution is valid.
    /// - `Err(EncodingError)` if the solution is malformed or unsupported.
    fn validate_solution(&self, solution: &Solution) -> Result<(), EncodingError>;
}
