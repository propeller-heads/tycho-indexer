# VM Integration

This page describes the interface required to implement protocol logic component.

To create a VM integration, it is required to provide a manifest file as well as an implementation of the corresponding adapter interface.

## Examples

Following exchanges have been integrated using VM approach:

- Uniswap V2 (see `/evm/src/uniswap-v2`)
- Balancer V2 (see `/evm/src/balancer-v2`)

## Step by step

### Prerequisites

1. Install [Foundry](https://book.getfoundry.sh/getting-started/installation#using-foundryup), start by downloading and installing the Foundry installer:
    ```bash
    curl -L https://foundry.paradigm.xyz | bash
    ```
    then start a new terminal session and run
    ```bash
   foundryup
    ```

1. Start by making a local copy of the Propeller Protocol Lib repository:
    ```bash
    git clone https://github.com/propeller-heads/propeller-protocol-lib
    ```

1. Install forge dependencies:
    ```bash
    cd ./propeller-protocol-lib/evm/
    forge install
    ```

### Understanding the ISwapAdapter

Read the the documentation of the [Ethereum Solidity interface](ethereum-solidity.md). It describes the functions that need to be implemented as well as the manifest file.
Additionally read through the docstring of the [ISwapAdapter.sol](../../../evm/src/interfaces/ISwapAdapter.sol) interface and the [ISwapAdapterTypes.sol](../../../evm/src/interfaces/ISwapAdapterTypes.sol) interface which defines the data types and errors used by the adapter interface.
You can also generate the documentation locally and the look at the generated documentation in the `./docs` folder:
   ```bash
   cd ./evm/
   forge doc
   ```
### Implementing the ISwapAdapter interface
Your integration should be in a separate directory in the `evm/src` folder. Start by cloning the template directory:
   ```bash
   cp ./evm/src/template ./evm/src/<your-adapter-name>
   ```
Implement the `ISwapAdapter` interface in the `./evm/src/<your-adapter-name>.sol` file. There are two reference implementations, one for Uniswap V2 and the other for Balancer V2. 

### Testing your implementation
Clone the `evm/test/TemplateSwapAdapter.t.sol` file and rename it to `<your-adapter-name>.t.sol`. Implement the tests for your adapter, make sure all implemented functions are tested and working correctly. Look at the examples of `UniswapV2SwapAdapter.t.sol` and `BalancerV2SwapAdapter.t.sol` for reference. The [Foundry test guide](https://book.getfoundry.sh/forge/tests) is a good reference, especially the chapter for [Fuzz testing](https://book.getfoundry.sh/forge/fuzz-testing), which is used in both the Uniswap and Balancer tests.

We are using fork testing, i.e. we are running a local Ethereum node and fork the mainnet state. This allows us to test the integration against the real contracts and real data. To run the tests, you need to set the `ETH_RPC_URL` environment variable to the URL of an ethereum RPC. It can be your own node or a public one, like [Alchemy](https://www.alchemy.com/) or [Infura](https://infura.io/).

Finally, run the tests with:
   ```bash
   cd ./evm
   forge test
   ```
