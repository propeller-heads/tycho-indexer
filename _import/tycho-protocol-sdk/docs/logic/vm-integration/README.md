# VM Integration

This page describes the interface required to implement protocol logic component.

To create a VM integration, it is required to provide a manifest file as well as an implementation of the corresponding adapter interface.

## Examples

Following exchanges have been integrated using VM approach:

- Uniswap V2 (see `/evm/src/uniswap-v2`)
- Balancer V2 (see `/evm/src/balancer-v2`)

## Step by step

### Prerequisites

1. Install [Foundry](https://book.getfoundry.sh/getting-started/installation#using-foundryup).
    ```bash
    curl -L https://foundry.paradigm.xyz | bash
    ```
    then start a new terminal session and run
    ```bash
   foundryup
    ```

2. Start by making a local copy of the Propeller Protocol Lib repository:
    ```bash
    git clone https://github.com/propeller-heads/propeller-protocol-lib
    ```

3. Install forge dependencies:
    ```bash
    cd ./propeller-protocol-lib/evm/
    forge install
    ```

### Understanding the ISwapAdapter

1. Read the the documentation of the [Ethereum Solidity interface](ethereum-solidity.md). It describes the functions that need to be implemented as well as the manifest file.
2. Additionally read through the docstring of the [ISwapAdapter.sol](../../../evm/src/interfaces/ISwapAdapter.sol) interface and the [ISwapAdapterTypes.sol](../../../evm/src/interfaces/ISwapAdapterTypes.sol) interface which defines the data types and errors used by the adapter interface.
3. You can also generate the documentation locally and the look at the generated documentation in the `./docs` folder:
   ```bash
   cd ./propeller-protocol-lib/evm/
   forge doc
   ```
### Implementing the ISwapAdapter interface
1. Your integration should be in a separate directory in the `evm/src` folder. Start by cloning the template directory:
   ```bash
   cp -r ./evm/src/template ./evm/src/<your-adapter-name>
   ```
2. Implement the `ISwapAdapter` interface in the `./evm/src/<your-adapter-name>.sol` file.
3. Create tests for your implementation in the `./evm/test/<your-adapter-name>.t.sol` file, again based on the template `./evm/test/TemplateSwapAdapter.t.sol`.

