# Protosim

Moves slow on-chain computations off-chain to solve optimization problems. 

This crate allows simulating a set of supported protocols off-chain. Currently, it has a focus on token exchange protocols, but it is not necessarily limited to this.

> **See also:**
> The `evm_simulation` module allows for simulating _any_ transaction; it is agnostic to protocol. See module's documentation.

To further help solve hard problems in the context of exchanging tokens, the crate provides the ProtoGraph structure, which can be queried for chained token exchanges and their parameters. This graph structure evolves over time as protocol states are changed by user actions. These changes are captured using events. The implemented protocols are aware of the state-mutating events and can transition their state correctly given such events.

## Currently supported protocols:

- Uniswap V2 and Forks
- Uniswap V3

See also `evm_simulation` module which can simulate any transaction.

## Adding a new Protocol

To add a new protocol, you will need to complete the following high-level steps:

1.  Create a protocol state struct that implements the `ProtocolSim` struct.
2.  Add associated events and implement the transition method on the protocol state struct.
3.  Register the events and state structs under `crate::protocol::state::ProtocolState` and `crate::protocol::state::ProtocolEvent`, respectively.

Each protocol should have its own module under `protosim/src/protocol`.

### 1\. Adding state & behaviour

Simply implement a struct that contains the state of the protocol. Only the attributes that are necessary to fulfill the `ProtocolSim` trait are required. Then, implement that trait.

```rust
/// ProtocolSim trait
/// This trait defines the methods that a protocol state must implement in order to be used
/// in the trade simulation.
#[enum_dispatch]
pub trait ProtocolSim {
    /// Returns the fee of the protocol as ratio
    ///
    /// E.g. if the fee is 1%, the value returned would be 0.01.
    fn fee(&self) -> f64;

    /// Returns the protocols current spot price of two tokens
    ///
    /// Currency pairs are meant to be compared against one another in
    /// order to understand how much of the quote currency is required
    /// to buy one unit of the base currency.
    ///
    /// E.g. if ETH/USD is trading at 1000, we need 1000 USD (quote)
    /// to buy 1 ETH (base currency).
    ///
    /// # Arguments
    ///
    /// * `a` - Base Token: refers to the token that is the quantity of a pair.
    ///     For the pair BTC/USDT, BTC would be the base asset.
    /// * `b` - Quote Token: refers to the token that is the price of a pair.
    ///     For the symbol BTC/USDT, USDT would be the quote asset.
    fn spot_price(&self, base: &ERC20Token, quote: &ERC20Token) -> f64;

    /// Returns the amount out given an amount in and input/output tokens.
    ///
    /// # Arguments
    ///
    /// * `amount_in` - The amount in of the input token.
    /// * `token_in` - The input token ERC20 token.
    /// * `token_out` - The output token ERC20 token.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `GetAmountOutResult` struct on success or a
    ///  `TradeSimulationError` on failure.
    fn get_amount_out(
        &self,
        amount_in: U256,
        token_in: &ERC20Token,
        token_out: &ERC20Token,
    ) -> Result<GetAmountOutResult, TradeSimulationError>;
}
```

### 2\. Adding Events

To transition the state, we need to implement the `transition` method. This method is not part of the `ProtocolSim` trait because the `enum_dispatch` crate cannot generate the correct code for it. Therefore, we need to handle this manually unless we write our own macro for this.

The `transition` method's signature is simple:

```rust
fn transition(&mut self, event: [EventType], logmeta: EVMLogMeta)
```

The `logmeta` should be used to ensure that the events are applied in the correct order. This is currently biased towards EVM-based chains, but you can use `crate::protocol::events::check_log_idx` to ensure that logs are being processed in the right order.

If a protocol supports multiple events, you can group them in a protocol-specific enum, and use that enum as a member of the `ProtocolEvent` enum. To make it easier, make sure to implement `From<YourProtocolEventEnum> for ProtocolEvent`. This will make it easier to convert from the protocol-specific enum to the generic one.

### 3\. Register Your DataStructures

As a final step, you will need to register your data structures. To do this, add your new state struct to the `crate::protocol::state::ProtocolState` enum. Additionally, add your new event enum to the `crate::protocol::state::ProtocolEvent` enum. Finally, add a match arm to the `ProtocolState.transition` method in `crate::protocol::state` to match on both the current state and the received event.

That should do it!