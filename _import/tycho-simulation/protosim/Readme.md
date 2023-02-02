# Protosim

Moves slow onchain computation offchain to solve optimization problems. This crate allows to simulate a set of supported protocols offchain. Currently it
has a focus on token exchange protocols but it is not necessarily limited to this.

To further help solving hard problems in the context of exchanging tokens, the crate provides a graph structure that can be queried for chained token
exchanges and their parameters. The graph structure evolves over time as protocol states are changed by user actions. These changes are captured using
events. The implemented protocols are aware of the state mutating events and can transition their state corrctly given such events.

## Adding a new Protocol

To add a new protocol the following high level steps are necessary:

1. Add a protocol state struct that implements the `ProtocolSim` struct
2. Finally add events and implement the transition method on the previously implemented protocol state struct
3. Finally register events and state struct under `crate::protocol::state::ProtocolState` and `crate::protocol::state::ProtocolEvent` enums respectively.

Each protocol is supposed to have it's own module under: `protosim/src/protocol`


## 1. Adding state & behaviour

Simply implement a struct that only contains the state of the protocol. Only the state attributes that are really required to fulfill the `ProtocolSim` trait 
is required. Next implement the trait:

```
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

### 2. Adding events

To transition the state we need to implement the transition method. It is not part of the ProtocolSim trait but it is necessary so we can properly implement
the method on the `ProtolState` enum. This method is not part of the ProtocolSim method because the `enum_dispatch` crate can not create the correct code for 
it, therefore we need to handle this manually unless we would write our own macro for this.

Anyway the transition methods signature is simple:

```
fn transition(&mut self, event: [EventType], logmeta: EVMLogMeta);
```

The logmeta should be used to ensure that the events are applied in the correct order. This is currently a bit biased torwards EVM based chains. You can use
`crate::protocol::events::check_log_idx` to ensure logs are being processed in the right order.

If a protocol supports multiple events, you can group the structs in a protocol specific enum, and that enum is later used as a member of the ProtocolEvent 
enum. For convinience make sure to implement the `From<YourProtocolEventEnum> for ProtocolEvent`. This will make it easy to convert from protocol specific 
enum to the generic one.

### 3. Register your datastructures

As a final step you want to register your data structures. This needs to be done in the following places:

- Add your new state struct to the `crate::protocol::state::ProtocolState` enum.
- Add your new event enum to the `crate::protocol::state::ProtocolEvent` enum.
- Add a match arm to the `ProtocolState.transition` method in `crate::protocol::state`, you need to match on both self (the curren state) and the received event.

That should be it.