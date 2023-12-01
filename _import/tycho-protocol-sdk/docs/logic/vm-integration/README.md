# VM Integration

This page describes the interface required to implement protocol logic component.

To create a VM implementation, it is required two provide a manifest file as well as a implementation of the corresponding adapter interface.

## Step by step

### Prerequisites

1. Start by making a local copy of the Propeller Protocol Lib repository:
```bash
git clone https://github.com/propeller-heads/propeller-protocol-lib
```

2. Install `Foundry`, the smart contract development toolchain we use. We recommend installation using [foundryup](https://book.getfoundry.sh/getting-started/installation#using-foundryup)

3. Install forge dependencies:
```bash
cd evm
forge install
```

4. Your integration should be in a separate directory in the `evm/src` folder. You can clone one of the example directories `evm/src/uniswap-v2` or `evm/src/balancer` and rename it to your integration name.
```