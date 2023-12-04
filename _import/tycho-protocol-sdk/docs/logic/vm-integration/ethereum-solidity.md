---
description: Provide protocol logic using the ethereum virtual machine
---

# Ethereum: Solidity

### Swap

To integrate an EVM exchange protocol the [ISwapAdapter.sol ](https://github.com/propeller-heads/propeller-protocol-lib/blob/main/evm/interfaces/ISwapAdapter.sol)should be implemented. Additionally a manifest file is required that summarises some metadata about the protocol.

{% hint style="info" %}
Although the interface is specified for Solidity, you are not limited to writing the adapater contract in solidity. We can use any compiled evm bytecode. So if you prefer e.g. Vyper  you are welcome to implement the interface using vyper. Unfortunately we do not provide all the tooling for vyper contracts yet, but you can certainly submit compiled vyper byte code.
{% endhint %}

The manifest file contains information about the author, as well as additional static information about the protocol and how to test the current implementation. The file below lists all valid keys.

```yaml
# Information about the author helps us to reach out in case of issues.
author:
  name: Propellerheads.xyz
  email: alan@propellerheads.xyz

# Protocol Constants
constants:
 # The minimum gas usage of the protocol, excluding any token transfers
  protocol_gas: 30000
  # Minimum capabilities we can expect, individual pools may extend these
  capabilities:
    - SellSide
    - BuySide
    - PriceFunction

# The files containing the adapter contract (byte)code
contract: 
  # The contract bytecode (required if no source is provided)
  runtime: UniswapV2SwapAdapter.bin
  # If you submit the source our CI can generate the bytecode
  source: UniswapV2SwapAdapter.sol

# Deployment instances used to generate chain specific bytecode.
# Used by the runtime bytecode build script.
instances:
  - chain:
      name: mainnet
      id: 0
    arguments:
      - "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"

# Specify some automatic test cases in case getPoolIds and
# getTokens are not implemented.
tests:
  instances:
    - pair_id: "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc"
      sell_token: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
      buy_token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
      block: 17000000
      chain:
        id: 0
        name: mainnet
```

#### Price (optional)

Calculates pair prices for specified amounts (optional).

The returned prices should include all protocol fees, in case the fee is dynamic, the returned price is expected to include the minimum fee.&#x20;

Ideally this method should be implemented, although it is optional as the price function can be numerically estimated from the swap function. In case it is not available it should be flagged accordingly via capabilities and calling it should revert using the NotImplemented error.&#x20;

The method needs to be implemented as view as this is usually more efficient and can be run in parallel.

```solidity
function price(
    bytes32 pairId,
    IERC20 sellToken,
    IERC20 buyToken,
    uint256[] memory sellAmounts
) external view returns (Fraction[] memory prices);
```

#### Swap

Simulates swapping tokens on a given pair.

This function should be state modifying meaning it should actually execute the swap and change the state of the vm accordingly.

Please include a gas usage estimate for each amount. This can be achieved e.g. by using the gasleft() function.

The return type Trade, has a price attribute which should contain the value of price(specifiedAmount). As previously mentioned, the price function support is optional, it is valid to return a zero value for this price in that case it will be estimated numerically. To return zero please use Fraction(0, 1).

```solidity
function swap(
    bytes32 pairId,
    IERC20 sellToken,
    IERC20 buyToken,
    OrderSide side,
    uint256 specifiedAmount
) external returns (Trade memory trade);
```

#### GetLimits

Retrieves the limits for each token.

This method returns the maximum limits of a token that can be traded. The limit is reached when the change in the received amounts is zero or close to zero. If in doubt over estimate the limit. The swap function should not error with LimitExceeded if called with any amounts below the limit.

```solidity
function getLimits(bytes32 pairId, OrderSide side)
    external
    returns (uint256[] memory);
```

#### getCapabilities

Retrieves the capabilities of the selected pair.

```solidity
function getCapabilities(bytes32 pairId, IERC20 sellToken, IERC20 buyToken)
    external
    returns (Capability[] memory);
```

#### getTokens (optional)

Retrieves the tokens for the given pair.

_Mainly used for testing as this is redundant with the required substreams implementation._

```solidity
function getTokens(bytes32 pairId)
    external
    returns (IERC20[] memory tokens);
```

#### getPoolIds (optional)

Retrieves a range of pool IDs.

_Mainly used for testing it is alright to not return all available pools here. Nevertheless this is useful to test against the substreams implementation. If implemented it safes time writing custom tests._

```solidity
function getPoolIds(uint256 offset, uint256 limit)
    external
    returns (bytes32[] memory ids);
```





