# EVM Simulation

Simulate any on-chain transaction, overriding the world state if needed.

The `SimulationEngine` leverages `revm` to simulate on-chain transactions, returning both transaction output and state
changes caused by the transaction. It also supports overriding account balances and storage slots.

To perform simulations, the engine requires access to the EVM state, provided by the `EngineDatabaseInterface` trait.
Two implementations of this trait are available:

`PreCachedDB`: Preloads necessary data such as contract code, storage slots, and balances. This implementation uses
Tycho
Indexer as its data source and offers the most efficient simulation experience.

`SimulationDB`: Queries an Ethereum node for required data and caches it for the duration of one block. It also supports
mocking accounts.

By default, `SimulationEngine` uses `PreCachedDB` for optimal efficiency. However, `SimulationDB` is available for
testing or
scenarios requiring dynamic queries.

## Overriding chain state

Terms used in this chapter:

- `engine` - An instance of `SimulationEngine`
- `state` - An instance of `EngineDatabaseInterface` that the `engine` is using

### Default behaviour

In the default setup, simulations execute as if they were performed on the current block, unless explicitly overridden.

### Overriding an account

Instead of relying on the database data, you can manually configure account information using
the `state.init_account()` method. This method accepts the following parameters:

```
address: Address,
account: AccountInfo,
permanent_storage: Option<HashMap<U256, U256>>,
mocked: bool,
```

- `AccountInfo`: Contains core account details like balance, nonce, and code (for smart contract accounts).
- `permanent_storage`: Allows setting predefined storage slots. During simulation, the engine will prioritise the slots
  listed here above those provided by the database.
- `mocked`: Determines whether the account is mocked (see below).

### Simulation-time overrides

You can override the chain state for the duration of a single simulation. This is done by
setting `SimulationParameters.overrides` to a mapping of form `[Address -> [slot -> value]]`.

Overrides set here take precedence over an account's permanent storage.

### SimulationDB

#### Mocked vs. Non-Mocked Accounts

- Non-Mocked Accounts (`mocked=false`):
    - Missing storage slots are queried from the Ethereum node.
- Mocked Accounts (`mocked=true`):
    - No data is queried from the node.
    - Missing storage slots default to 0 if they are not set in either permanent storage or simulation-time overrides.

This is particularly useful if you are overriding the contract code to be different from on chain code, because the
storage slots might be different.

#### See also

- An example of usage: `evm::simulation::tests::test_integration_revm_v2_swap`