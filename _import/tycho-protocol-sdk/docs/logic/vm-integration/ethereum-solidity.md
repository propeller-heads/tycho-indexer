---
description: Provide protocol logic using the ethereum virtual machine
---

# Ethereum: Solidity

## Swap/exchange protocol

To integrate an EVM exchange protocol the [ISwapAdapter.sol ](https://github.com/propeller-heads/propeller-protocol-lib/blob/main/evm/interfaces/ISwapAdapter.sol)should be implemented. Additionally, a manifest file is required that summarises some metadata about the protocol.

{% hint style="info" %}
Although the interface is specified for Solidity, you are not limited to writing the adapter contract in Solidity. We can use any compiled evm bytecode. So if you prefer e.g. Vyper, you are welcome to implement the interface using Vyper. Unfortunately we do not provide all the tooling for Vyper contracts yet, but you can certainly submit compiled Vyper byte code.
{% endhint %}

The manifest file contains information about the author, as well as additional static information about the protocol and how to test the current implementation. The file below lists all valid keys.

```yaml
# Information about the author helps us to reach out in case of issues.
author:
  name: Propellerheads.xyz
  email: alan@propellerheads.xyz

# Protocol Constants
constants:
 # The minimum gas usage of a swap using the protocol, excluding any token transfers
  protocol_gas: 30000
  # Minimum capabilities we can expect, individual pools may extend these.
  # To learn about Capabilities, see ISwapAdapter.sol
  capabilities:
    - SellSide
    - BuySide
    - PriceFunction

# The files containing the adapter contract (byte)code
contract: 
  # The contract runtime (i.e. deployed) bytecode (required if no source is provided)
  runtime: UniswapV2SwapAdapter.bin
  # If you submit the source our CI can generate the bytecode
  source: UniswapV2SwapAdapter.sol

# Deployment instances used to generate chain-specific bytecode.
# Used by the runtime bytecode build script.
instances:
  - chain:
      name: mainnet
      id: 1
    # Arguments passed to the constructor when building the contract
    arguments:
      - "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"

# Specify some automatic test cases in case getPoolIds and
# getTokens are not implemented.
tests:
  instances:
    - pool_id: "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc"
      sell_token: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
      buy_token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
      block: 17000000
      chain:
        name: mainnet
        id: 1
```

#### Price (optional)

Calculates pool prices for specified amounts (optional).

The returned prices should be in `buyToken/sellToken` units. 

The returned prices should include all protocol fees. In case the fee is dynamic, the returned price is expected to include the minimum fee.

Ideally this method should be implemented, although it is optional as the price function can be numerically estimated from the swap function. In case it is not available, it should be flagged accordingly via capabilities, and calling it should revert using the NotImplemented error.

The method needs to be implemented as view as this is usually more efficient and can be run in parallel.

```solidity
function price(
    bytes32 poolId,
    IERC20 sellToken,
    IERC20 buyToken,
    uint256[] memory sellAmounts
) external view returns (Fraction[] memory prices);
```

#### Swap

Simulates swapping tokens on a given pool.

This function should be state modifying, meaning it should actually execute the swap and change the state of the VM accordingly.

Please include a gas usage estimate for each amount. This can be achieved e.g. by using the `gasleft()` function.

The return type `Trade` has a price attribute which should contain the value of `price(specifiedAmount)`. As previously mentioned, the price function support is optional, it is valid to return a zero value for this price (in that case it will be estimated numerically). To return zero please use `Fraction(0, 1)`.

```solidity
function swap(
    bytes32 poolId,
    IERC20 sellToken,
    IERC20 buyToken,
    OrderSide side,
    uint256 specifiedAmount
) external returns (Trade memory trade);
```

#### GetLimits

Retrieves the limits for each token.

This method returns the maximum amount of a token that can be traded. The limit is reached when the change in the received amounts is zero or close to zero. If in doubt, overestimate the limit. The swap function should not error with LimitExceeded if called with any amounts below the limit.

```solidity
function getLimits(bytes32 poolId, OrderSide side)
    external
    returns (uint256[] memory);
```

#### getCapabilities

Retrieves the capabilities of the selected pool.

```solidity
function getCapabilities(bytes32 poolId, IERC20 sellToken, IERC20 buyToken)
    external
    returns (Capability[] memory);
```

#### getTokens (optional)

Retrieves the tokens for the given pool.

_Mainly used for testing as this is redundant with the required substreams implementation._

```solidity
function getTokens(bytes32 poolId)
    external
    returns (IERC20[] memory tokens);
```

#### getPoolIds (optional)

Retrieves a range of pool IDs.

_Mainly used for testing. It is alright to not return all available pools here. Nevertheless, this is useful to test against the substreams implementation. If implemented, it saves time writing custom tests._

```solidity
function getPoolIds(uint256 offset, uint256 limit)
    external
    returns (bytes32[] memory ids);
```
