---
description: >-
  Tycho Execution offers an encoding tool (a Rust crate for generating swap
  calldata) and execution components (Solidity contracts). This is how
  everything works together.
---

# Code Architecture

The following diagram summarizes the code architecture:

<figure><img src="../../../.gitbook/assets/Tycho (1).svg" alt=""><figcaption></figcaption></figure>

### Encoding

The `TychoRouterEncoder` and `TychoExecutorEncoder` are responsible for validating the solutions of orders and providing you with a list of transactions that you must execute against the `TychoRouter` or `Executor`s.&#x20;

The `TychoRouterEncoder` uses a `StrategyEncoder` that it choses automatically depending on the solution (see more about strategies [here](../../../concepts.md#strategy)).

Internally, both encoders choose the appropriate `SwapEncoder`(s) to encode the individual swaps, which depend on the protocols used in the solution.&#x20;

### Execution

The `TychoRouter` calls one or more `Executor`s (corresponding with the output of the `SwapEncoder`s) to interact with the correct protocol and perform each swap of the solution. The `TychoRouter` optionally verifies that the user receives a minimum amount of the output token.

If you select the `ExecutorStrategyEncoder` during setup, you must execute the outputted calldata directly against the `Executor` which corresponds to the solution’s swap’s protocol. Beware that you are responsible for performing any necessary output amount checks. This strategy is useful if you want to call Tycho executors through your own router. For more information direct execution, see [here](../../../for-solvers/execution/executing.md#executing-directly-to-the-executor-contract).
