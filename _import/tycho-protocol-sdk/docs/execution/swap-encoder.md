# Implementing a SwapExecutor for a Protocol

## Overview

The `SwapStructEncoder` interface is designed to encode the necessary data for a swap, which will be used by the `SwapExecutor` to interact with a liquidity pool. The encoder is responsible for structuring the swap details, including the input/output tokens, pool addresses, and any additional protocol-specific parameters.

Each protocol must implement its own `SwapStructEncoder` and ensure that the swap data is correctly encoded for the `SwapExecutor`.

### Dev environment

- Run `aws codeartifact login --tool pip --repository protosim --domain propeller` so you can access the propeller packages.
- Create the dev environment `conda env create -f propeller-swap-encoders/environment_dev.yaml`
- Activate it with `conda activate propeller-swap-encoders`
- Install dependencies with `pip install -r propeller-swap-encoders/requirements.txt`
- Should you get a pyyaml installation error execute the following command: `pip install "cython<3.0.0" && pip install --no-build-isolation pyyaml==5.4.1`

You can import the abstract class `SwapStructEncoder` from `propeller-solver-core` in your python code like:
```python
from core.encoding.interface import SwapStructEncoder
```

## Key Methods

This is the `SwapStructEncoder` interface can be found [here](https://github.com/propeller-heads/defibot/blob/7ea38b92e60e182471f513c2aeef0370c4b3766a/propeller-solver-core/core/encoding/interface.py#L31).

- **encode_swap_struct**
  - **Purpose**: To encode the swap details into a bytes object that the SwapExecutor can use to execute the swap.
  - **Parameters**:
    - `swap`: A dictionary containing the swap details. These are the fields present in this dict:
      - `pool_id: str`: The identifier for the liquidity pool where the swap will occur.
      - `sell_token: EthereumToken`: The token that will be sold in the swap (e.g., DAI).
      - `buy_token: EthereumToken`: The token that will be bought in the swap (e.g., WETH).
      - `split: float`: Indicates how the swap should be split between pools (often set to 0).
      - `sell_amount: int`: The amount of the sell token to be used in the swap.
      - `buy_amount: int`: The amount of the buy token to be received from the swap.
      - `token_approval_needed: bool`: A boolean indicating if token approval is needed before the swap.
      - `pool_tokens`: An optional tuple containing additional token data specific to the pool.
      - `pool_type: str`: The type of pool where the swap will be executed (e.g., "BalancerStablePoolState").
    - `receiver`: The address that will receive the output tokens from the swap.
    - `encoding_context`: Additional context information necessary for encoding (see more [here](https://github.com/propeller-heads/defibot/blob/7ea38b92e60e182471f513c2aeef0370c4b3766a/propeller-solver-core/core/encoding/interface.py#L9))
    - `**kwargs`: Any additional protocol-specific parameters that need to be included in the encoding.
  - **Returns**: A bytes object containing the encoded swap data.

## Implementation Steps

1. **Define Protocol-Specific Encoding Logic**: Implement the `encode_swap_struct` function to encode the swap details specific to the protocol. This may include encoding token addresses, pool addresses, and other necessary parameters into a bytes format.
2. **Compatibility with SwapExecutor**: Ensure that the encoded data is compatible with the `SwapExecutor` implementation for the protocol. The `SwapExecutor` will rely on this data to perform the swap accurately.
3. **Testing**: Thoroughly test the encoding process with various swap scenarios to ensure that the encoded data is correct and that the `SwapExecutor` can process it without errors.



## Example Implementation

See the example implementation of a `SwapExecutor` for Balancer [here](../../propeller-swap-encoders/propeller_swap_encoders/balancer.py) and test [here](../../propeller-swap-encoders/propeller_swap_encoders/tests/test_balancer.py).