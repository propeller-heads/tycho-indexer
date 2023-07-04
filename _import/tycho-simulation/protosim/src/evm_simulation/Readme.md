# EVM Simulation

Simulate any on-chain transaction, overriding the world state if needed.

`simulation::SimulationEngine` can simulate an on-chain transaction and return tx output and state changes caused by that transaction.

To do that, the engine needs access to the EVM state. This is provided by `database::SimulationDB`. This struct queries an ethereum node for needed data and caches it for a duration of 1 block. It also allows for setting up mocked accounts and overriding account balances and storage slots.

## Overriding chain state

Terms used in this chapter:
- `engine` - an instance of `SimulationEngine`
- `state` - an instance of `SimulationDB` that the `engine` is using

### Default behaviour

In a vanilla engine, if nothing is explicitly done to override a state, simulations happen as if they were executed on current block.

Whenever some data needed by the engine is not present in the state, the state queries an Ethereum node for this data. This way the engine gets basic information about accounts (such as balance, nonce and code) as well as accounts' storage (values stored by smart contracts).

These values are cached until `state.clear_temp_storage()` is called.

### Overriding an account

Instead of querying account information or storage from a node, we can set it manually.

This is done with `state.init_account()` method which takes the following arguments:
- account address
- `AccountInfo` instance
- permanent storage mapping
- `mocked` boolean

`AccountInfo` contains basic account information such as balance, nonce and code (in case of smart contract accounts).

Permanent storage lets us set some storage slots. If a value of a certain storage slot is needed during simulation, the state will first check the permanent storage set here. Only if a slot is not set in the permanent storage, the state will query an Ethereum node (but see the next section).

The next section describes the `mocked` argument.

### Mocked and non-mocked accounts

An overriden account may be set as mocked or non-mocked.

For non-mocked accounts (`mocked=false`), missing storage slots will be queried from a node.

For mocked accounts (`mocked=true`), nothing will be queried from a node. Missing slots have value of 0: if a certain storage slot is needed during simulation, but has neither been set in the account's permanent storage (see the previous section) nor in the simulation-time overrides (see the next section), then the value of such slot will be 0.

If you are overriding contract code, you most probably want to set the account to be mocked. That's because overridden code might use different storage slots than the code on-chain, so querying a node for storage of such account wouldn't make sense.

### Simulation-time overrides

You can override the chain state only for the duration of a single simulation. This is done by setting `SimulationParameters.overrides` to a mapping of form `address -> storage slot index -> storage slot value`.

Overrides set this way will take priority over accounts' permanent storage and querying from a node.


## See also
- An example of usage: `simulation::tests::test_integration_revm_v2_swap`
- Using this module from Python: `protosim_py` module
- Using this module to implement a PoolState in defibot: https://github.com/propeller-heads/defibot/blob/master/defibot/swaps/protosim/Readme.md
