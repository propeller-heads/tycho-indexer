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

This is the `SwapStructEncoder` interface:

```python
class SwapStructEncoder(ABC):
    """Encodes a PercentageSwap of a certain protocol to be used in our SwapRouterV2
    Should be subclassed for each protocol that we support.
    """

    @abstractmethod
    def encode_swap_struct(
        self, swap: dict[str, Any], receiver: Address, **kwargs
    ) -> bytes:
        pass
```

- **encode_swap_struct**
  - **Purpose**: To encode the swap details into a bytes object that the SwapExecutor can use to execute the swap.
  - **Parameters**:
    - `swap`: A dictionary containing the swap details, such as input/output token addresses, amounts, and pool information.
    - `receiver`: The address that will receive the output tokens from the swap.
    - `**kwargs`: Any additional protocol-specific parameters that need to be included in the encoding.
  - **Returns**: A bytes object containing the encoded swap data.

## Implementation Steps

1. **Define Protocol-Specific Encoding Logic**: Implement the `encode_swap_struct` function to encode the swap details specific to the protocol. This may include encoding token addresses, pool addresses, and other necessary parameters into a bytes format.
2. **Compatibility with SwapExecutor**: Ensure that the encoded data is compatible with the `SwapExecutor` implementation for the protocol. The `SwapExecutor` will rely on this data to perform the swap accurately.
3. **Testing**: Thoroughly test the encoding process with various swap scenarios to ensure that the encoded data is correct and that the `SwapExecutor` can process it without errors.



## Example Implementation

See the example implementation of a `SwapExecutor` for Balancer [here](../../propeller-swap-encoders/propeller_swap_encoders/balancer.py) and test [here](../../propeller-swap-encoders/propeller_swap_encoders/tests/test_balancer.py).