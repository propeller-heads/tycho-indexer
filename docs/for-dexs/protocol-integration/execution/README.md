# Execution

To integrate a new protocol into Tycho, you need to implement two key components:

1. **SwapEncoder** (Rust struct) – Handles swap encoding.
2. **Executor** (Solidity contract) – Executes the swap on-chain.

See more about our code architecture [here](code-architecture.md).

## Encoder Interface

Each new protocol requires a dedicated `SwapEncoder` that implements the `SwapEncoder` trait. This trait defines how swaps for the protocol are encoded into calldata.

```rust
fn encode_swap(
    &self,
    swap: Swap,
    encoding_context: EncodingContext,
) -> Result<Vec<u8>, EncodingError>;
```

This function encodes a swap and its relevant context information into calldata that is compatible with the `Executor` contract. The output of the `SwapEncoder` is the input of the `Executor` (see next section). We recommend using packed encoding to save gas. See current implementations [here](https://github.com/propeller-heads/tycho-execution/tree/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/src/encoding/evm/swap_encoder).

If your protocol needs some specific constant addresses please add them in [config/protocol\_specific\_addresses.json](https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/config/protocol_specific_addresses.json).

After implementing your `SwapEncoder` , you need to:

* Add your protocol with a placeholder address in: [config/executor\_addresses.json](https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/config/executor_addresses.json) and [config/test\_executor\_addresses.json](https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/config/test_executor_addresses.json)
* Add your protocol in the [`SwapEncoderRegister`](https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/src/encoding/evm/swap_encoder/swap_encoder_registry.rs#L38) (if you want it to be one of the default protocols)

<details>

<summary>Protocols Supporting Consecutive Swap Optimizations</summary>

As described in the [Swap Group](../../../for-solvers/execution/encoding/#swap-group) section, our encoding supports protocols which save token transfers between consecutive swaps using systems such as flash accounting. In such cases, as shown in the diagram below using Uniswap V4 as an example, the `SwapEncoder` is still only in charge of encoding a **single swap**. These swaps will then be concatenated at the `StrategyEncoder` level as a single executor call.

Depending on the index of the swap in the swap group, the encoder may be responsible for adding additional information which is not necessary in other swaps of the sequence (see the first swap in the diagram below).

<figure><img src="../../../.gitbook/assets/both (1).svg" alt=""><figcaption><p>Diagram representing swap groups</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/encoding data opt.svg" alt=""><figcaption><p>Output of a SwapEncoder for a group swap</p></figcaption></figure>

</details>

## Swap Interface

Every integrated protocol requires its own swap executor contract. This contract must implement the [`IExecutor`](https://github.com/propeller-heads/tycho-contracts/blob/main/foundry/interfaces/IExecutor.sol) interface. See currently implemented executors [here](https://github.com/propeller-heads/tycho-contracts/tree/main/foundry/src/executors). Please also look through our [Contributing Guidelines for Solidity](../contributing-guidelines.md#changing-solidity-code).

The `IExecutor` interface requires three methods:

#### `swap`

```solidity
function swap(uint256 amountIn, bytes calldata data, address receiver)
    external
    payable;
```

Called by the Dispatcher via `delegatecall`. This function:

* Accepts the input amount (`amountIn`). The input amount is calculated at execution time, not during encoding, to account for possible slippage.
* Processes the swap using the provided calldata (`data`), which is the output of the `SwapEncoder`.
* Sends output tokens to `receiver`.
* Does not return any `amountOut` - for security purposes, this information is automatically detected using balance checks in the `Dispatcher`

**Important:** Executors must not transfer **any** ERC20 tokens. All input and output token transfers are handled by the Dispatcher (via the `TransferManager`). The only exception is native ETH — executors that interact with protocols requiring ETH as `msg.value` (e.g., Fluid, Rocketpool) handle this themselves and declare `TransferNativeInExecutor` as their transfer type.

#### `getTransferData`

```solidity
function getTransferData(bytes calldata data)
    external
    payable
    returns (
        TransferManager.TransferType transferType,
        address receiver,
        address tokenIn,
        address tokenOut,
        bool outputToRouter
    );
```

Called by the Dispatcher via `staticcall` before each swap to determine how input tokens should be transferred. The executor returns:

* `transferType`: How the protocol expects to receive tokens (see [Token Transfers](./#token-transfers)).
* `receiver`: Where tokens should be sent (typically the pool address or the router).
* `tokenIn`: The input token address.
* `tokenOut`: The output token address.
* `outputToRouter`: Whether the protocol automatically sends the output token back to the TychoRouter. The Dispatcher uses this to decide whether it needs to transfer the token to the intended receiver.

`transferType`, `receiver` and `outputToRouter` must be **hardcoded** per-executor based on the protocol's requirements — they are not encodable in calldata.

#### `fundsExpectedAddress`

```solidity
function fundsExpectedAddress(bytes calldata data)
    external
    returns (address receiver);
```

Used during [sequential swaps](../../../concepts.md#sequential) to determine where the **previous** swap should send its output tokens. For example, in a route WBTC → USDC → DAI, before executing the first swap, the Dispatcher calls `fundsExpectedAddress` on the second executor to decide where to send USDC.

* Return the pool address if the protocol accepts direct transfers (e.g., Uniswap V2 pools).
* Return `msg.sender` (the router) if the protocol expects tokens in the router (e.g., callback-based protocols).

### Callbacks

Some protocols require a callback during swap execution (e.g., Uniswap V3, Uniswap V4, Balancer V3). In these cases, the executor contract must also implement [`ICallback`](https://github.com/propeller-heads/tycho-contracts/blob/main/foundry/interfaces/ICallback.sol).

**Required Methods**

```solidity
function handleCallback(
    bytes calldata data
) external returns (bytes memory result);

function verifyCallback(bytes calldata data) external view;

function getCallbackTransferData(bytes calldata data)
    external
    payable
    returns (
        TransferManager.TransferType transferType,
        address receiver,
        address tokenIn,
        uint256 amountIn
    );
```

* `handleCallback`: The main entry point for handling callbacks.
* `verifyCallback`: Should be called within `handleCallback` to ensure that the `msg.sender` is a valid pool from the expected protocol.
* `getCallbackTransferData`: Called by the Dispatcher during the callback to determine how tokens should be transferred. Like `getTransferData`, the transfer type must be hardcoded — the Dispatcher handles the actual transfer based on the returned values.

**Callback Flow**

When a protocol initiates a callback during swap execution, it flows through the `TychoRouter`'s `fallback()` method, which acts as the entry point for all callback requests. The router's fallback function delegates the call to the Dispatcher, which:

1. Calls `getCallbackTransferData` on the executor to determine transfer requirements.
2. Performs the token transfer via the `TransferManager` (the executor does not transfer tokens itself).
3. Calls `handleCallback` on the executor to complete the swap interaction.

The callback data passed through this flow should include the function selector and all necessary information for the executor to complete the swap operation, such as token addresses, amounts, and any protocol-specific parameters required by the pool contract.

## Token Transfers

**Executors do not handle any token transfers**. All ERC20 token transfers are orchestrated by the Dispatcher via the [`TransferManager`](https://github.com/propeller-heads/tycho-contracts/blob/main/foundry/src/TransferManager.sol). The Dispatcher calls `getTransferData` (or `getCallbackTransferData` during callbacks) on the executor to learn _how_ the protocol expects to receive tokens, and then performs the transfer itself.

This design reduces the attack surface — a malicious or buggy executor cannot misroute user funds because it never touches the input token directly.

#### TransferType

Each executor must return a hardcoded `TransferManager.TransferType` from `getTransferData` (and `getCallbackTransferData` for callback executors). The available types are:

| Transfer Type              | Description                                                                                                                                                                            |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Transfer`                 | The Dispatcher transfers tokens to the pool (or router) before calling `swap`. Used by protocols that expect tokens to be present in the pool before the swap call (e.g., Uniswap V2). |
| `ProtocolWillDebit`        | The protocol pulls tokens from the router via an approval. The Dispatcher approves the protocol to spend the required amount. Used by protocols like Curve and Balancer V2.            |
| `TransferNativeInExecutor` | The executor sends native ETH as `msg.value` during the swap. The Dispatcher only performs accounting — no ERC-20 transfer occurs. Used by protocols like Fluid and Rocketpool.        |
| `None`                     | No transfer is needed at this point. Typically returned by `getTransferData` for callback-based protocols where the transfer happens inside the callback instead.                      |

**The only case where an executor handles a token transfer is native ETH** (`TransferNativeInExecutor`). For all ERC-20 tokens, the Dispatcher is solely responsible for transfers.

#### How the Dispatcher Resolves Transfers

Before each swap, the Dispatcher:

1. Calls `getTransferData` on the executor to get the `TransferType`, `receiver`, token addresses, and whether the protocol sends out tokens back to the router automatically.
2. Determines the transfer strategy based on the swap context (first swap vs. subsequent, split swap, vault-funded, etc.).
3. Performs the input token transfer via the `TransferManager`.

After each swap, the Dispatcher:

1. Performs a balance check to determine the token output amount of the swap
2. If `outputToRouter` is true, forwards output tokens to swap receiver

For sequential swaps, the Dispatcher also calls `fundsExpectedAddress` on the _next_ executor to decide where the current swap should send its output tokens — either directly to the next pool or back to the router.

The transfer behavior is fully determined by the values your executor returns from `getTransferData` and `fundsExpectedAddress`.

### Native Token Address Handling

When encoding swaps, you may need to handle address conversions for native tokens.

#### Converting Zero Address to Protocol-Specific Address

Tycho uses the zero address (`0x0000000000000000000000000000000000000000`) to represent native tokens across all chains during indexing and simulation. However, if your protocol's contracts expect a different address convention—such as `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE`—you must convert the address when encoding.

**In your `SwapEncoder` implementation:**

1. Check if the input or output token is the zero address
2. If your protocol requires a different sentinel address for native tokens, convert it in the encoding step
3. Ensure the conversion happens only in the calldata generation, not in the protocol state

This ensures compatibility with your protocol's on-chain contracts while maintaining Tycho's standardized native token representation throughout indexing and simulation.

## Fee Tokens

Balance checks before and after token transfers mean fee-on-transfer tokens and rebasing tokens work on most protocols. The exception is Uniswap V3-like protocols, which require declaring the input swap amount when calling swap but only transfer the input token in the callback.

## Testing

Each new integration must be thoroughly tested in both Rust and Solidity. This includes:

* Unit tests for the `SwapEncoder` in Rust
* Unit tests for the `Executor` in Solidity
* Two key **integration tests** to verify the full swap flow: `SwapEncoder` to `Executor` integration test and a full TychoRouter integration test

#### 1. `SwapEncoder` ↔ `Executor` integration test

Verify that the calldata generated by the `SwapEncoder` is accepted by the corresponding `Executor`.

Use the helper functions:

* `write_calldata_to_file()` in the encoding module (Rust)
* `loadCallDataFromFile()` in the execution module (Solidity)

These helpers save and load the calldata to/from `calldata.txt`.

#### 2. Full TychoRouter Integration Test

* In `tests/protocol_integration_tests.rs`, write a Rust test that encodes a single swap and saves the calldata using `write_calldata_to_file()`.
* In `TychoRouterTestSetup`, deploy your new executor and add it to executors list in `deployExecutors`.
* Run the setup to retrieve your executor’s deployed address and add it to [config/test\_executor\_addresses.json](https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/config/test_executor_addresses.json).
* Create a new Solidity test contract that inherits from `TychoRouterTestSetup`. For example:

```solidity
 contract TychoRouterForYouProtocolTest is TychoRouterTestSetup {
    function getForkBlock() public pure override returns (uint256) {
        return 22644371; // Use a block that fits your test scenario
    }

    function testSingleYourProtocolIntegration() public {
        ...
    }
}
```

These tests ensure your integration works end-to-end within Tycho’s architecture.

## Deploying and Whitelisting

Once your implementation is approved:

1. **Deploy the executor contract** on the appropriate network (more [here](https://github.com/propeller-heads/tycho-execution/blob/0454514f4f6ccff55dcaa8e3abbb4ac494d89eba/foundry/scripts/README.md)).
2. **Contact us** to whitelist the new executor address on our main router contract.
3. **Update the configuration** by adding the new executor address to `executor_addresses.json` and register the `SwapEncoder` within the `SwapEncoderBuilder` .

By following these steps, your protocol will be fully integrated with Tycho.
