# Testing

We provide a comprehensive testing suite for Substreams modules. The suite facilitates end-to-end testing and ensures your Substreams modules function as expected. For unit tests, please use standard [Rust unit testing practices](https://doc.rust-lang.org/book/ch11-01-writing-tests.html).

## What is tested?

The testing suite runs [Tycho Indexer](https://github.com/propeller-heads/tycho-indexer) with your Substreams implementation for a specific block range. It verifies that the end state matches the expected state specified by the testing YAML file. This confirms that your Substreams package is indexable and that it outputs what you expect.

Next the suite simulates transactions using [Tycho Simulation](https://github.com/propeller-heads/tycho-simulation) engine. This will verify that all necessary data is indexed and that the provided `SwapAdapter` contract works as intended.

{% hint style="warning" %}
It is important to know that the simulation engine runs entirely off-chain and only accesses the data and contracts you index (token contracts are mocked and don't need to be indexed).
{% endhint %}

## Test Configuration

Inside your Substreams directory, you need an [integration\_test.tycho.yaml ](https://github.com/propeller-heads/tycho-protocol-sdk/blob/main/substreams/ethereum-template-factory/integration_test.tycho.yaml)file. This test template file already outlines everything you need. But for clarity, we expand on some test configs here:

#### 1. `skip_balance_check`

By default, this should be `false`. Testing verifies the balances reported for the component by comparing them to the on-chain balances of the `Component.id` .This should be set to `false` if:

1. the `Component.id` does not correlate to a contract address;
2. balances are not stored on the component's contract (i.e. they're stored on a vault).

If this skip is set to `true`, you must comment on why.

#### 2. `initialized_accounts`

This is a list of contract addresses that simulation requires, although their creation is not indexed within the test block range. Leave empty if not required.&#x20;

Importantly, this config is used during **testing only**. Your Substreams package should still properly initialise the accounts listed here. This configuration only eliminates the need to include historical blocks that contain the initialisation events in your test data. This is useful to ensure tests are targeted and quick to run.

You can use the `initialized_accounts` config at two levels in the test configuration file:

* [global](https://github.com/propeller-heads/tycho-protocol-sdk/blob/main/substreams/ethereum-template-factory/integration_test.tycho.yaml#L25): accounts listed here are used for all tests in this suite,
* [test level](https://github.com/propeller-heads/tycho-protocol-sdk/blob/main/substreams/ethereum-template-factory/integration_test.tycho.yaml#L39): accounts listed here are scoped to that test only.

#### 5. `expected_components`

This is a list of components whose creation you are testing. It includes all component data (tokens, static attributes, etc.). You do not need to include _all_ components created within your test block range; only those on which the test should focus.

#### 4. `skip_simulation`

By default this should be set to `false` . It should only be set to `true` temporarily if you want to isolate testing the indexing phase only; or for extenuating circumstances (like testing indexing a pool type that simulation doesn't yet support). If set to `true`, you must comment on why.

## Troubleshooting

### Slow tests

An integration test should take a maximum of 5–10 minutes. If the tests take longer, here are key things you can explore:

1. Ensure you have **no infinite loops** within your code.
2. Ensure you are using a **small block range** for your test, ideally below 1,000 blocks. The blocks in your test only need to cover the creation of the component you are testing. Optionally, they can extend to blocks with changes for the component you want the test to cover. To help limit the test block range, you could explore the [initialized\_accounts](./#id-2.-initialized_accounts) config.
3. Ensure you are **not indexing tokens**. Token contracts use a lot of storage, so fetching their historical data is slow. Instead, they are mocked on the simulation engine and don't have to be explicitly indexed. Make an exception if they have unique behavior, like acting as both a token and a pool, or rebasing tokens that provide a `getRate`method.

Note: Substreams uses cache to improve speed up subsequent runs of the same module. A test's first run is always slower than subsequent runs, unless you adjust the Substreams module.

### Account not initialised

There are two main causes for this error:

1. Your Substreams package is not indexing a contract that is necessary for simulations.
2. Your test begins at a block that is later than the block on which the contract was created. To fix this, add the missing contract to the [initialized\_accounts](./#id-2.-initialized_accounts) test config.

### Debugging

For enhanced debugging, we recommend running the testing module with the --tycho-logs flag. This will enable Tycho-indexer logs.

