# Tycho Execution

TODO: add banner

Tycho Execution makes it easy to trade on different DEXs by handling the complex encoding for you. Instead of creating
custom code for each DEX, you get a simple, ready-to-use tool that generates the necessary data to execute trades. It's
designed to be safe, straightforward, and quick to set up, so anyone can start trading without extra effort.

## Usage Guide

### Encoding Transactions

To encode a transaction, you can pipe a JSON payload to the `tycho-encode` binary:

```bash
echo '<json_payload>' | cargo run --bin tycho-encode
```

#### Example

Here's a complete example that encodes a swap from WETH to DAI using Uniswap V2:

```bash
echo '{"sender":"0x1234567890123456789012345678901234567890","receiver":"0x1234567890123456789012345678901234567890","given_token":"0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2","given_amount":"1000000000000000000","checked_token":"0x6B175474E89094C44Da98b954EedeAC495271d0F","exact_out":false,"slippage":0.01,"expected_amount":"1000000000000000000","check_amount":"990000000000000000","router_address":"0xaa820C29648D5EA543d712cC928377Bd7206a0E7","swaps":[{"component":{"id":"0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640","protocol_system":"uniswap_v2","protocol_type_name":"UniswapV2Pool","chain":"ethereum","tokens":["0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"],"contract_ids":["0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"],"static_attributes":{"factory":"0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f"},"change":"Update","creation_tx":"0x0000000000000000000000000000000000000000000000000000000000000000","created_at":"2024-02-28T12:00:00"},"token_in":"0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2","token_out":"0x6B175474E89094C44Da98b954EedeAC495271d0F","split":1.0}],"direct_execution":false}' | cargo run
```

#### JSON Payload Structure

The input JSON payload requires the following fields:

- `sender`: The address initiating the transaction
- `receiver`: The address receiving the output tokens
- `given_token`: The address of the input token (e.g., WETH)
- `given_amount`: The amount of input tokens (in wei)
- `checked_token`: The address of the output token (e.g., DAI)
- `exact_out`: Boolean indicating if this is an exact output swap
- `slippage`: The maximum allowed slippage (e.g., 0.01 for 1%)
- `expected_amount`: The expected output amount
- `check_amount`: The minimum acceptable output amount (accounting for slippage)
- `swaps`: Array of swap steps, each containing:
  - `component`: Details about the DEX/protocol being used
  - `token_in`: Input token address for this step
  - `token_out`: Output token address for this step
  - `split`: Proportion of tokens to route through this step (1.0 = 100%)
- `router_address`: The address of the protocol's router contract
- `direct_execution`: Boolean indicating if the transaction should be executed directly

## Contract Analysis

We use [Slither](https://github.com/crytic/slither) to detect any potential vulnerabilities in our contracts.

To run locally, simply install Slither in your conda env and run it inside the foundry directory.

```bash
conda create --name tycho-execution python=3.10
conda activate tycho-execution

pip install slither-analyzer
cd foundry
slither .
```