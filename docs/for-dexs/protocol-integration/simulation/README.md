# Simulation

To enable simulations for a newly added protocol, it must first be integrated into the Tycho Simulation repository. Please submit a pull request to the [repository](https://github.com/propeller-heads/tycho-simulation) to include it.

## Native Integration

In order to add a new native protocol, you will need to complete the following high-level steps:

1. Create a protocol state struct that contains the state of the protocol, and implements the `ProtocolSim` trait (see [here](https://github.com/propeller-heads/tycho-simulation/blob/a50b24dc1cd2421719eb5f6a636b4fa8a9e8cd78/src/protocol/state.rs#L64)).
2. Create a tycho decoder for the protocol state: i.e. implement `TryFromWithBlock` for `ComponentWithState` to your new protocol state.

Each native protocol should have its own module under `tycho-simulation/src/evm/protocol`.

## VM Integration

To create a VM integration, provide a manifest file and an implementation of the corresponding adapter interface. [Tycho Protocol SDK ](https://github.com/propeller-heads/tycho-protocol-sdk)is a library to integrate DEXs and other onchain liquidity protocols into Tycho.

### Example Implementations <a href="#example-implementations" id="example-implementations"></a>

The following exchanges are integrated with the VM approach:

* Balancer V2 (see code [here](https://github.com/propeller-heads/tycho-protocol-sdk/blob/main/evm/src/balancer-v2/BalancerV2SwapAdapter.sol))

### Install prerequisites <a href="#install-prerequisites" id="install-prerequisites"></a>

1.  Install [Foundry](https://book.getfoundry.sh/getting-started/installation#using-foundryup), start by downloading and installing the Foundry installer:

    ```bash
    curl -L https://foundry.paradigm.xyz | bash
    ```

    then start a new terminal session and run

    ```bash
    foundryup
    ```
2.  Clone the Tycho Protocol SDK:

    ```bash
    git clone https://github.com/propeller-heads/tycho-protocol-lib
    ```
3.  Install dependencies:

    ```bash
    cd ./tycho-protocol-lib/evm/
    forge install
    ```

### Understanding the ISwapAdapter <a href="#understanding-the-iswapadapter" id="understanding-the-iswapadapter"></a>

Read the documentation of the [Ethereum Solidity](ethereum-solidity.md) interface. It describes the functions that need to be implemented and the manifest file.

Additionally, read through the docstring of the [ISwapAdapter.sol](https://github.com/propeller-heads/propeller-venue-lib/blob/main/evm/src/interfaces/ISwapAdapter.sol) interface and the [ISwapAdapterTypes.sol](https://github.com/propeller-heads/propeller-venue-lib/blob/main/evm/src/interfaces/ISwapAdapterTypes.sol) interface, which defines the data types and errors the adapter interface uses. You can also generate the documentation locally and look at the generated documentation in the `./docs` folder:

```bash
cd ./evm/
forge doc
```

### Implementing the ISwapAdapter interface <a href="#implementing-the-iswapadapter-interface" id="implementing-the-iswapadapter-interface"></a>

Your integration should be in a separate directory in the `evm/src` folder. Start by cloning the template directory:

```bash
cp ./evm/src/template ./evm/src/<your-adapter-name>
```

Implement the `ISwapAdapter` interface in the `./evm/src/<your-adapter-name>.sol` file. See Balancer V2 implementation for reference.

### Testing your implementation <a href="#testing-your-implementation" id="testing-your-implementation"></a>

1. Set up test files:
   * Copy `evm/test/TemplateSwapAdapter.t.sol`
   * Rename to `<your-adapter-name>.t.sol`
2. Write comprehensive tests:
   * Test all implemented functions.
   * Use fuzz testing (see [Foundry test guide](https://book.getfoundry.sh/forge/tests), especially the chapter for [Fuzz testing](https://book.getfoundry.sh/forge/fuzz-testing))
   * Reference existing test files: `BalancerV2SwapAdapter.t.sol`
3. Configure fork testing (run a local mainnet fork against actual contracts and data):
   * Set `ETH_RPC_URL` environment variable
   * Use your own Ethereum node or services like [Infura](https://infura.io/)
4.  Run the tests with

    ```bash
    cd ./evm
    forge test
    ```

### Add implementation to Tycho simulation

Once you have the swap adapter implemented for the new protocol, you will need to:

1.  Generate the adapter runtime file by running the [`evm/scripts/buildRuntime.sh`](https://github.com/propeller-heads/tycho-protocol-sdk/blob/115e552f2f7ac99cc07289e0367a98f221862d7e/evm/scripts/buildRuntime.sh)  script in our SDK repository with the proper input parameters.\
    \
    For example, in order to build the `Balancer V2` runtime, the following command can be run:\


    ```
    >>> cd evm
    >>> ./scripts/buildRuntime.sh -c “BalancerV2SwapAdapter” -s “constructor(address)” -a “0xBA12222222228d8Ba445958a75a0704d566BF2C8”
    ```


2. Add the associated adapter runtime file to `tycho-simulations/src/protocol/vm/assets`. Make sure to name the file according to the protocol name used by Tycho Indexer in the following format: `<Protocol><Version>Adapter.evm.runtime`. For example: `vm:balancer_v2` will be `BalancerV2Adapter.evm.runtime`. Following this naming format is important as we use an automated name resolution for these files.

### Filtering

If your implementation does not support all pools indexed for a protocol, you can create a filter function to handle this. This filter can then be used when registering an exchange in the `ProtocolStreamBuilder`. See [here](https://github.com/propeller-heads/tycho-simulation/blob/03d845a363836e6371e10e9f24d9c7f2042fa4db/src/evm/protocol/filters.rs) for example implementations.
