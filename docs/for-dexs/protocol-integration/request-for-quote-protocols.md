# Request for Quote Protocols

To add support for a new RFQ provider in Tycho, you’ll need to implement a client, a state, and the logic to encode and execute trades.&#x20;

The state, encoding, and execution logic for RFQs follow the same structure as on-chain protocol integrations. See our [simulation](simulation/) and [execution](execution/) guides for details.

We recommend using the existing Bebop integration as a reference.

### RFQClient

Each RFQ protocol must implement the `RFQClient` trait:

```rust
#[async_trait]
pub trait RFQClient: Send + Sync {
    fn stream(
        &self,
    ) -> BoxStream<'static, Result<(String, StateSyncMessage<TimestampHeader>), RFQError>>;

    async fn request_binding_quote(
        &self,
        params: &GetAmountOutParams,
    ) -> Result<SignedQuote, RFQError>;
}
```

Responsibilities:

* **stream**: Connects to the RFQ provider and emits real-time indicative price updates.
* **request\_binding\_quote**: Sends an HTTP request to fetch a binding quote for a specific swap.

You’ll also need to provide a builder to configure and construct your client, similar to `BebopClientBuilder`.

### State

Each provider must define a state object that represents a full snapshot of their indicative prices.

This state must implement:

* `ProtocolSim` for simulation
* `TryFromWithBlock` to decode incoming messages into a usable state

Details on how to implement these can be found [here](simulation/#native-integration).

### Encoder + Executor

To support execution, implement:

* **Encoder**: Encodes the calldata to execute a swap on the RFQ via the Tycho Router. Be sure to request the binding quote here.&#x20;
* **Executor**: Executes the swap

For more see [here](execution/).

This allows the RFQ to be used in hybrid routes and benefit from Tycho’s execution optimizations.
