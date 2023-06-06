# EVM Simulation

Simulate any on-chain transaction, overriding the world state if needed.

`simulation::SimulationEngine` can simulate an on-chain transaction and return tx output and state changes caused by that transaction.

To do that, the engine needs access to the EVM state. This is provided by `database::SimulationDB`. This struct queries an ethereum node for needed data and caches it for a duration of 1 block. It also allows for setting up mocked accounts and overriding account balances and storage slots.

## See also
- An example of usage: `simulation::tests::test_integration_revm_v2_swap`
- Using this module from Python: `protosim_py` module
