# Substreams Testing

This package provides a comprehensive testing suite for Substreams modules. The testing suite is designed to facilitate
end-to-end testing, ensuring that your Substreams modules function as expected.

## Overview

The testing suite builds the `.spkg` for your Substreams module, indexes a specified block range, and verifies that the
expected state has been correctly indexed in PostgreSQL.
Additionally, it will also try to simulate some transactions using the `SwapAdapter` interface.

## Prerequisites

- Latest version of our tycho-indexer binary, placed in a directory that is included in your system’s PATH. Ask us for the binary, or follow [these instructions](https://github.com/propeller-heads/tycho-indexer/tree/main/tycho-indexer#build-tycho-indexer-binary) on our tycho-indexer repo.
- Docker installed on your machine.
- [Conda](https://conda.io/projects/conda/en/latest/user-guide/install/index.html)
  and [AWS cli](https://aws.amazon.com/cli/) installed

## Test Configuration

Tests are defined in a `yaml` file. A documented template can be found at
`substreams/ethereum-template/integration_test.tycho.yaml`. The configuration file should include:

- The target Substreams config file.
- The corresponding SwapAdapter and args to build it.
- The expected protocol types.
- The tests to be run.

Each test will index all blocks between `start-block` and `stop-block`, verify that the indexed state matches the
expected state and optionally simulate transactions using `SwapAdapter` interface.

You will also need the VM Runtime file for the adapter contract.
Our testing script should be able to build it using your test config.
The script to generate this file manually is available under `evm/scripts/buildRuntime.sh`.

## Set up testing environment

## Prerequisites

Before setting up the Python environment, ensure the following tools and libraries are installed on your system:

- **Git**: Version control tool (https://git-scm.com/)
- **Rust**: Programming language and toolchain (https://www.rust-lang.org/)
- **GCC**: GNU Compiler Collection (https://gcc.gnu.org/)
- **libpq**: PostgreSQL client library (https://www.postgresql.org/docs/9.5/libpq.html)
- **OpenSSL (libssl)**: OpenSSL development library (https://github.com/openssl/openssl)
- **pkg-config**: Helper tool for managing compiler flags (https://www.freedesktop.org/wiki/Software/pkg-config/)
- **Conda**: Python package manager (https://docs.conda.io/en/latest/)
- **pip**: Python package installer (https://pip.pypa.io/)

Run the setup env script. It will create a conda virtual env and install all dependencies.
```bash
./setup_env.sh
```

This script must be run from within the `tycho-protocol-sdk/testing` directory.

Lastly, you need to activate the conda env:
```bash
conda activate tycho-protocol-sdk-testing
```

## Running Tests

### Prerequisites

This section requires a testing environment setup. If you don’t have it yet, please refer to the [set up testing
environment section](#set-up-testing-environment).

### Step 1: Export Environment Variables

Export the required environment variables for the execution. You can find the available environment variables in the
`.env.default` file.
Please create a `.env` file inside the `testing` directory and set the required environment variables.

#### Environment Variables

**RPC_URL**

- **Description**: The URL for the Ethereum RPC endpoint. This is used to fetch the storage data. The node needs to be
  an archive node, and support [debug_storageRangeAt](https://www.quicknode.com/docs/ethereum/debug_storageRangeAt).
- **Example**: `export RPC_URL="https://ethereum-mainnet.core.chainstack.com/123123123123"`

**SUBSTREAMS_API_TOKEN**

- **Description**: The API token for accessing Substreams services. This token is required for authentication.
- **Example**: `export SUBSTREAMS_API_TOKEN=eyJhbGci...`

### Step 2: Set up tests

If you do not have one already, you will need to build the wasm file of the package you wish to test. This can be done by navigating to the package directory and running:
```bash
cargo build --target wasm32-unknown-unknown --release
```

Then, run a local postgres test database using docker compose. This needs to be done from within the testing directory.
```bash
docker compose up -d db
```

### Step 3: Run tests

Run tests for your package. This must be done from the main project directory.

```bash
python ./testing/src/runner/cli.py --package "your-package-name"
```

#### Example

If you want to run tests for `ethereum-balancer-v2`, use:

```bash
conda activate tycho-protocol-sdk-testing
export RPC_URL="https://ethereum-mainnet.core.chainstack.com/123123123123"
export SUBSTREAMS_API_TOKEN=eyJhbGci...
cd testing
docker compose up -d db
cd ..
python ./testing/src/runner/cli.py --package "ethereum-balancer-v2"
```

#### Testing CLI args

A list and description of all available CLI args can be found using:

```
python ./testing/src/runner/cli.py --help
```
