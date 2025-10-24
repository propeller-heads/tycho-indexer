# Encoding

first step to execute a trade on chain is encoding.

Our Rust [crate](https://github.com/propeller-heads/tycho-execution/tree/main/src) offers functionality to convert your trades into calldata, which the Tycho contracts can execute.

See this [Quickstart](../../#id-4.-encode-a-swap) section for an example of how to encode your trade.

## Models

These are the models used as input and output of the encoding crate.&#x20;

### Solution Struct

The `Solution` struct specifies the details of your order and how it should be filled. This is the input of the encoding module.&#x20;

The `Solution` struct consists of the following attributes:

<table><thead><tr><th width="190" align="center">Attribute</th><th width="218.13671875" align="center">Type</th><th>Description</th></tr></thead><tbody><tr><td align="center"><strong>given_token</strong></td><td align="center"><code>Bytes</code></td><td>The token being sold (exact in) or bought (exact out)</td></tr><tr><td align="center"><strong>given_amount</strong></td><td align="center"><code>BigUint</code></td><td>Amount of the given token</td></tr><tr><td align="center"><strong>checked_token</strong></td><td align="center"><code>Bytes</code></td><td>The token being bought. This token's final balance will be checked by the router using  <code>checked_amount</code>.</td></tr><tr><td align="center"><strong>sender</strong></td><td align="center"><code>Bytes</code></td><td>Address of the sender of the given token</td></tr><tr><td align="center"><strong>receiver</strong></td><td align="center"><code>Bytes</code></td><td>Address of the receiver of the checked token</td></tr><tr><td align="center"><strong>exact_out</strong></td><td align="center"><code>bool</code></td><td>False if the solution is an exact input solution (i.e. solves a sell order). <strong>Currently only exact input solutions are supported</strong>.</td></tr><tr><td align="center"><strong>router_address</strong></td><td align="center"><code>Bytes</code></td><td>Address of the router contract to be used. See Tycho addresses <a href="contract-addresses.md">here</a>.</td></tr><tr><td align="center"><strong>swaps</strong></td><td align="center"><code>Vec&#x3C;Swap></code></td><td>List of swaps to fulfil the solution.</td></tr><tr><td align="center"><strong>checked_amount</strong></td><td align="center"><code>BigUint</code></td><td>Minimum amount out to be checked for the solution to be valid if passing through the <code>TychoRouter</code>. </td></tr><tr><td align="center"><strong>native_action</strong></td><td align="center"><code>Option&#x3C;NativeAction></code></td><td>If set, the native token will be wrapped before the swap or unwrapped after the swap (more <a href="encoding.md#wrapping-and-unwrapping">here</a>).</td></tr><tr><td align="center"><strong>user_data</strong></td><td align="center"><code>Option&#x3C;Bytes></code></td><td>Additional user data that can be passed to encoding.</td></tr></tbody></table>

#### Wrapping and Unwrapping

Our router accepts wrapping native tokens to wrapped token before performing the first swap, and unwrapping wrapped tokens to native tokens after the final swap, before sending the funds to the receiver.

In order to perform this, the `native_action` parameter of the solution must be set to either `Some(NativeAction.WRAP)` or `Some(NativeAction.UNWRAP)`.

When wrapping:

* The `given_token` of the **solution** should be ETH
* The `token_in` of the **first swap** should be WETH

When unwrapping:

* The `checked_token` of the **solution** should be ETH
* The `token_out` of the **final swap** should be WETH

### Swap Struct

A solution consists of one or more swaps. A swap represents a swap operation to be performed on a pool.

The `Swap` struct has the following attributes:

| Attribute           |              Type              |                                                        Description                                                        |
| ------------------- | :----------------------------: | :-----------------------------------------------------------------------------------------------------------------------: |
| **component**       |       `ProtocolComponent`      |                                             Protocol component from Tycho core                                            |
| **token\_in**       |             `Bytes`            |                                               Token you provide to the pool                                               |
| **token\_out**      |             `Bytes`            |                                               Token you expect from the pool                                              |
| **split**           |              `f64`             |                  Percentage of the amount in to be swapped in this operation (for example, 0.5 means 50%)                 |
| **user\_data**      |         `Option<Bytes>`        |                                        Optional user data to be passed to encoding                                        |
| **protocol\_state** | `Option<Arc<dyn ProtocolSim>>` |                                      Optional protocol state used to perform the swap                                     |
| **protocol\_state** |        `Option<BigUint>`       | Optional estimated amount in for this Swap. This is necessary for RFQ protocols. This value is used to request the quote. |

To create a `Swap`, use the [SwapBuilder](https://github.com/propeller-heads/tycho-execution/blob/6d88d0a1444da2e3d951b11257c322c62c3dd6f5/src/encoding/models.rs#L130) where you can pass any struct that implements `Into<ProtocolComponent>`.

#### Split Swaps

Solutions can have **splits** where one or more token hops are split between two or more pools. This means that the output of one swap can be split into several parts, each used as the input for subsequent swaps. The following are examples of different split configurations:

<figure><img src="../../.gitbook/assets/splits (2).svg" alt=""><figcaption><p>Diagram representing examples of split swaps</p></figcaption></figure>

By combining splits creatively, you can build highly customized and complex trade paths.

We perform internal validation on split swaps. A split swap is considered valid if:   &#x20;

1. The checked token is reachable from the given token through the swap path
2. There are no tokens that are unconnected
3. Each split amount is small than 1 (100%) and larger or equal to 0 (0%)
4. For each set of splits, set the split for the last swap to 0. This tells the router to send all tokens not assigned to the previous splits in the set (i.e., the remainder) to this pool.
5. The sum of all non-remainder splits for each token is smaller than 1 (100%)

<details>

<summary>Example Solution</summary>

The following diagram shows a swap from ETH to DAI through USDC. ETH arrives in the router and is wrapped to WETH. The solution then splits between three (WETH, USDC) pools and finally swaps from USDC to DAI on one pool.

<figure><img src="../../.gitbook/assets/split (1).svg" alt=""><figcaption><p>Diagram of an example solution</p></figcaption></figure>

The `Solution` object for the given scenario would look as follows:

<pre class="language-rust"><code class="lang-rust">swap_a = Swap::new(
    pool_a,
    weth_address,
    usdc_address,
    0.3, // 30% of WETH amount
);
swap_b = Swap::new(
    pool_b,
    weth_address,
    usdc_address,
    0.3, // 30% of WETH amount
);
swap_c = Swap::new(
    pool_c,
    weth_address,
    usdc_address,
    0f64, // Rest of remaining WETH amount (40%)
);
swap_d = Swap::new(
    pool_d,
    usdc,
    dai,
    0f64, // All of USDC amount
);

<strong>let solution = Solution {
</strong>    sender: user_address,
    receiver: user_address,
    given_token: eth_address,
    given_amount: sell_amount,
    checked_token: dai_address,
    exact_out: false, // Sell order
    slippage: None, // Do not perform slippage check
    expected_amount: None, // Do not perform slippage check
    checked_amount: min_amount_out,
    native_action: Some(NativeAction::Wrap),
    swaps: vec![swap_a, swap_b, swap_c, swap_d],
    native_action: Some(NativeAction.WRAP) // Wrap ETH to WETH before first swap
};
</code></pre>

</details>

### Swap Group <a href="#swap-group" id="swap-group"></a>

Certain protocols, such as Uniswap V4, allow you to save token transfers between consecutive swaps thanks to their flash accounting. In case your solution contains sequential (non-split) swaps of such protocols, our encoders compress these consecutive swaps into a single **swap group**,\
meaning that a **single call to our executor** is sufficient for performing these multiple swaps.

<figure><img src="../../.gitbook/assets/both.svg" alt=""><figcaption><p>Diagram representing swap groups</p></figcaption></figure>

In the example above, the encoder will compress three consecutive swaps into the following swap group to call the Executor:

```rust
SwapGroup {
    input_token: weth_address,
    output_token: dai_address,
    protocol_system: "uniswap_v4",
    swaps: vec![weth_wbtc_swap, wbtc_usdc_swap, usdc_dai_swap],
    split: 0,
}
```

One solution will contain multiple swap groups if different protocols are used.

### **Encoded Solution struct**

The output of encoding is `EncodedSolution`. It has the following attributes.

| Attribute             |          Type          |                                      Description                                     |
| --------------------- | :--------------------: | :----------------------------------------------------------------------------------: |
| **swaps**             |        `Vec<u8>`       |                          The encoded calldata for the swaps.                         |
| **interacting\_with** |         `Bytes`        | The address of the contract to be called (it can be the Tycho Router or an Executor) |
| **selector**          |        `String`        |                      The selector of the function to be called.                      |
| **n\_tokens**         |         `usize`        |                          The number of tokens in the trade.                          |
| **permit**            | `Option<PermitSingle>` |             Optional permit object for the trade (if permit2 is enabled).            |

## Encoders

Tycho Execution provides two main encoder types:

* **TychoRouterEncoder**: This encoder prepares calldata for execution via the **Tycho Router** contract. It supports complex swap strategies, including multi-hop and split swaps. Use this when you want Tycho to handle routing and execution within its own router contract.
* **TychoExecutorEncoder**: This encoder prepares calldata for **direct execution** of individual swaps using the **Executor contracts**, bypassing the router entirely. It encodes one swap at a time and is ideal when integrating Tycho Executors into your own router contract. See more details [here](executing.md#executing-directly-to-the-executor-contract).

Choose the encoder that aligns with how you plan to route and execute trades.

### Builder

For each encoder, there is a corresponding builder:

* **TychoRouterEncoderBuilder**
* **TychoExecutorEncoderBuilder**

Both builders require the target **chain** to be set.

<details>

<summary><strong>Builder Options</strong></summary>

Both encoders have the following options:

* `executors_addresses` JSON string with the executor addresses to be used during encoding (defaults to the values in `config/executor_addresses.json`)

The router builder includes the following configuration options:

* `user_transfer_type: UserTransferType` Defines how the funds will be transferred from the user. The options are `TransferFromPermit2`, `TransferFrom` and `None`  (see more about token transfers [here](./#token-allowances)).
* `router_address` Router address to use for execution (defaults to the address corresponding to the given chain in `config/router_addresses.json`). See Tycho addresses [here](contract-addresses.md).

- ~~`swapper_pk: String`~~ (deprecated and will be removed soon) Used only for permit2 transfers. The private key is used to sign the permit object. This is only necessary when you want to retrieve the full calldata directly (which is not recommended - see more in the next section).

Use these options to customize how token movement and permissions are handled during encoding.

</details>

#### **Builder Example Usage**

{% tabs %}
{% tab title="RouterEncoder" %}
```rust
let encoder = TychoRouterEncoderBuilder::new()
    .chain(Chain::Ethereum)
    .user_transfer_type(UserTransferType::TransferFromPermit2)
    .build()
    .expect("Failed to build encoder");
```
{% endtab %}

{% tab title="ExecutorEncoder" %}
```rust
let encoder = TychoExecutorEncoderBuilder::new()
    .chain(Chain::Ethereum)
    .build()
    .expect("Failed to build encoder");
```
{% endtab %}
{% endtabs %}

### Encode

You can convert solutions into calldata using:&#x20;

```rust
let encoded_solutions = encoder.encode_solutions(solutions);
```

This method returns a `Vec<`[`EncodedSolution`](encoding.md#encoded-solution-struct)`>`, which contains only the encoded swaps of the solutions. It does **not** build the full calldata. You must encode the full method call yourself. If you are using Permit2 for token transfers, you need to sign the permit object as well.

The full method call includes the following parameters, which act as **execution guardrails:**

* `amountIn` and `tokenIn` – the amount and token to be transferred into the TychoRouter/Executor from you
* `minAmountOut` and `tokenOut` – the minimum amount you want to receive of token out. For maximum security, this min amount should be determined from a **third party source**.
* `receiver` – who receives the final output
* `wrap/unwrap` flags – if native token wrapping is needed
* `isTransferFromAllowed` – if this should perform a `transferFrom` to retrieve the input funds. This will be false if you send tokens to the router in the same transaction before the swap. &#x20;

These **execution guardrails** protect against exploits such as MEV. Correctly setting these guardrails yourself gives you full control over your swap security and ensures that the transaction cannot be exploited in any way.

Refer to the [quickstart](../../) code for an example of how to convert an `EncodedSolution` into full calldata. You must tailor this example to your use case to ensure that arguments are safe and correct. See the functions defined in the `TychoRouter` contract for reference.

<details>

<summary>Encoding during development/testing</summary>

:warning: There is another method in our encoder that you can use for testing purposes.

```rust
let transaction = encoder.encode_full_calldata(solutions);
```

This method returns full `Transaction` structs, ready to submit. It uses our example encoding logic internally (i.e., `encode_tycho_router_call`), which is meant for development and prototyping only.\
We do **not recommend using this in production**, as it takes control away from you and may not meet your security or routing needs. :warning:

</details>

## **Run as a Binary**

### Installation

First, build and install the binary:

```bash
# Build the project
cargo build --release

# Install the binary to your system
cargo install --path .
```

After installation, you can use the `tycho-encode` command from any directory in your terminal.&#x20;

### Commands

The command lets you choose the encoder:&#x20;

* `tycho-router`: Encodes a transaction using the `TychoRouterEncoder`.&#x20;
* `tycho-execution`: Encodes a transaction using the `TychoExecutorEncoder`.&#x20;

The commands accept the same options as the builders (more [here](encoding.md#builder-options)).

**Example**

Here's a complete example that encodes a swap from WETH to DAI using Uniswap V2 and the `TychoRouterEncoder` with Permit2 on Ethereum:

```bash
echo '{"sender":"0x1234567890123456789012345678901234567890","receiver":"0x1234567890123456789012345678901234567890","given_token":"0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2","given_amount":"1000000000000000000","checked_token":"0x6B175474E89094C44Da98b954EedeAC495271d0F","exact_out":false,"checked_amount":"990000000000000000","swaps":[{"component":{"id":"0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640","protocol_system":"uniswap_v2","protocol_type_name":"UniswapV2Pool","contract_addresses":[], "chain":"ethereum","tokens":["0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"],"contract_ids":["0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"],"static_attributes":{"factory":"0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f"},"change":"Update","creation_tx":"0x0000000000000000000000000000000000000000000000000000000000000000","created_at":"2024-02-28T12:00:00"},"token_in":"0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2","token_out":"0x6B175474E89094C44Da98b954EedeAC495271d0F","split":0.0}],"direct_execution":true}' | tycho-encode --chain ethereum --user-transfer-type transfer-from-permit2 tycho-router
```

