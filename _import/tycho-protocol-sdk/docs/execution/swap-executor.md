# Implementing a SwapExecutor for a Protocol

## Overview

The `ISwapExecutor` interface is designed to perform swaps on a liquidity pool. 
It allows for flexible interaction by accepting either the amount of the input token or the amount of the output token 
as parameters, returning the corresponding swapped amount. 
This interface is essential for creating a `SwapExecutor` specific to a protocol.

## Key Methods

- **swap(uint256 givenAmount, bytes calldata data)**
  - **Purpose**: To perform a token swap, either specifying the input amount to get the output amount or vice versa.
  - **Parameters**:
    - `givenAmount`: The amount of the token (input or output) for the swap.
    - `data`: Encoded information necessary for the swap (e.g., pool address, token addresses - depends on the protocol).
  - **Returns**: The amount of the token swapped.

## Implementation Steps

1. **Define Protocol-Specific Logic**: Implement the `swap` function to interact with the protocol's liquidity pool. 
Use the `data` parameter to encode necessary information like pool and token addresses.
2. **Handling Input and Output**: Depending on the provided `givenAmount`, determine whether it's an input or output 
swap. Calculate the corresponding swapped amount based on the pool's pricing logic.
3. **Error Handling**: Use `ISwapExecutorErrors` (`InvalidParameterLength` and `UnknownPoolType`) to manage potential 
errors, such as invalid parameter lengths or unknown pool types in the swap logic.
4. **Token Approvals**: If the protocol requires token approvals (allowances) before swaps can occur, 
manage these approvals within the implementation to ensure smooth execution of the swap.
5. **Token Transfer Support**: Ensure that the implementation supports transferring received tokens to a designated 
receiver address, either within the swap function or through an additional transfer step.
6. **Gas Efficiency**: Ensure the implementation is gas-efficient, ideally using assembly where possible, 
though it is not mandatory. Strive for optimal performance in the swap logic
7. **Security Considerations**: Follow common security best practices, such as validating inputs, ensuring proper 
access control, and safeguarding against reentrancy attacks.



## Example Implementation

See the example implementation of a `SwapExecutor` for Balancer here (TODO: paste link)