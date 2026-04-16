# TokenProxy

`TokenProxy.sol` is a smart contract designed to act as a proxy for any ERC20 token, allowing selective override of standard ERC20 functionality while preserving access to the original token's logic. The contract enables custom logic for metadata (name, symbol, decimals, totalSupply), balances, and approvals, which can be set and managed independently from the underlying implementation. If a custom value is not set, calls are transparently forwarded to the original ERC20 contract via proxy/fallback mechanisms. This design allows for flexible extension, patching, or simulation of ERC20 tokens without losing compatibility with the original contract's interface and behavior.

**Key features:**
- Override ERC20 metadata, balances, and approvals on a per-field or per-account basis.
- All other calls are forwarded to the original implementation using a fallback delegatecall.
- Custom storage slots are used to avoid collisions with the implementation contract.
- Useful for testing, simulation, or patching ERC20 tokens in a controlled environment.



## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

-   **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
-   **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
-   **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
-   **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy

```shell
$ forge script script/Counter.s.sol:CounterScript --rpc-url <your_rpc_url> --private-key <your_private_key>
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```

### Generate bin
````shell
solc --optimize --bin-runtime --abi src/TokenProxy.sol -o assets
````
