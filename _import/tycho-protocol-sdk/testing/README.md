# Substreams Testing

This package provides a comprehensive testing suite for Substreams modules. The testing suite is designed to facilitate end-to-end testing, ensuring that your Substreams modules function as expected.

## Overview

The testing suite builds the `.spkg` for your Substreams module, indexes a specified block range, and verifies that the expected state has been correctly indexed in PostgreSQL.

## Prerequisites

- Latest version of our indexer, Tycho. Please contact us to obtain the latest version. Once acquired, place it in the `/testing/` directory.
- Access to PropellerHeads' private PyPI repository. Please contact us to obtain access.
- Docker installed on your machine.

## Test Configuration

Tests are defined in a `yaml` file. A template can be found at
`substreams/ethereum-template/integration_test.tycho.yaml`. The configuration file should include:

- The target Substreams config file.
- The expected protocol types.
- The tests to be run.

Each test will index all blocks between `start-block` and `stop-block` and verify that the indexed state matches the expected state.

You will also need the EVM Runtime file for the adapter contract. 
The script to generate this file is available under `evm/scripts/buildRuntime.sh`.
Please place this Runtime file under the respective `substream` directory inside the `evm` folder.

## Running Tests

### Step 1: Export Environment Variables

Export the required environment variables for the execution. You can find the available environment variables in the `.env.default` file.
Please create a `.env` file in the `testing` directory and set the required environment variables.

#### Environment Variables

**SUBSTREAMS_PACKAGE**
- **Description**: Specifies the Substreams module that you want to test
- **Example**: `export SUBSTREAMS_PACKAGE=ethereum-balancer`

**DATABASE_URL**
- **Description**: The connection string for the PostgreSQL database. It includes the username, password, host, port, and database name. It's already set to the default for the Docker container.
- **Example**: `export DATABASE_URL="postgres://postgres:mypassword@localhost:5431/tycho_indexer_0`

**RPC_URL**
- **Description**: The URL for the Ethereum RPC endpoint. This is used to fetch the storage data. The node needs to be an archive node, and support [debug_storageRangeAt](https://www.quicknode.com/docs/ethereum/debug_storageRangeAt).
- **Example**: `export RPC_URL="https://ethereum-mainnet.core.chainstack.com/123123123123"`

**SUBSTREAMS_API_TOKEN**
- **Description**: The API token for accessing Substreams services. This token is required for authentication.
- **Example**: `export SUBSTREAMS_API_TOKEN=eyJhbGci...`

**DOMAIN_OWNER**
- **Description**: The domain owner identifier for Propellerhead's AWS account, used for authenticating on the private PyPI repository.
- **Example**: `export DOMAIN_OWNER=123456789`

### Step 2: Build and the Testing Script

To build the testing script, run the following commands:
```bash
source pre_build.sh
docker compose build
docker compose run app
```