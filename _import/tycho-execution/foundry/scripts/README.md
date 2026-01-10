# How to deploy

- Install dependencies `npm install`
- `cd foundry`

## Deploy on a Tenderly fork

1. Make a new [fork](https://dashboard.tenderly.co/) in tenderly dashboard for the
   chain that you wish to deploy on.
2. Set the following environment variables:

```
export RPC_URL=<fork-rpc-from-tenderly>
export DEPLOY_WALLET=<wallet-address>
export PRIVATE_KEY=<private-key>
```

3. Fund wallet: `npx hardhat run scripts/fund-wallet-tenderly-fork.js --network tenderly`

## Deploy on Ethereum Mainnet or Base

Make sure to run `unset HISTFILE` in your terminal before setting the private key. This will prevent the private key
from being stored in the shell history.

1. Set the following environment variables:

```
export RPC_URL=<chain-rpc-url>
export DEPLOY_WALLET=<wallet-address>
export PRIVATE_KEY=<private-key>
export BLOCKCHAIN_EXPLORER_API_KEY=<blockchain-explorer-api-key>
```

## Deploy Tycho Router

For each of the following, you must select one of `tenderly_ethereum`, `tenderly_base`,
`ethereum`, `base`, or `unichain` as the network.

1. Deploy router: `npx hardhat run scripts/deploy-router.js --network NETWORK`
2. Define the accounts to grant roles to in `scripts/roles.json`
3. Export the router address to the environment variable `export ROUTER_ADDRESS=<router-address>`
4. Grant roles: `npx hardhat run scripts/set-roles.js --network NETWORK`
5. Set executors: `npx hardhat run scripts/set-executors.js --network NETWORK`. Make sure you change the
   DEPLOY_WALLET to the executor deployer wallet. If you need to deploy executors, follow the instructions below.

### Deploy executors

1. In `scripts/deploy-executors.js` define the executors to be deployed
2. Deploy executors: `npx hardhat run scripts/deploy-executors.js --network NETWORK`
3. Fill in the executor addresses in `config/executor_addresses.json`

### Remove executors

1. If you set a new executor for the same protocol, you need to remove the old one.
2. Run: `npx hardhat run scripts/remove-executor.js --network NETWORK`
3. There will be a prompt for you to insert the executor address you want to remove.

### Revoke roles

1. If you wish to revoke a role for a certain address, run: `npx hardhat run scripts/revoke-role.js --network NETWORK`
2. There will be a prompt for you to insert the role hash and the address you want to revoke it for.

### Safe wallet

1. If the wallet that has the role, is a Gnosis Safe, you need to set the `SAFE_ADDRESS` env var.
2. The scripts deploy-executors, remove-executor, set-roles and revoke-role all support this.
    1. If `SAFE_ADDRESS` is set, then it will propose a transaction to the safe wallet and later on it needs to be
       approved in their UI to execute on chain. Be sure to change the PRIVATE_KEY to that which has permissions on the
       safe wallet.
    2. If it's not set, it will submit the transaction directly to the chain.

## Deploy Uniswap X filler

The current script deploys an Uniswap X filler and verifies it in the corresponding blockchain explorer.

Make sure to run `unset HISTFILE` in your terminal before setting the private key. This will prevent the private key
from being stored in the shell history.

1. Set the following environment variables:

```
export RPC_URL=<chain-rpc-url>
export PRIVATE_KEY=<deploy-wallet-private-key>
export BLOCKCHAIN_EXPLORER_API_KEY=<blockchain-explorer-api-key>
```

2. Confirm that the variables `tychoRouter`, `uniswapXReactor` and `nativeToken` are correctly set in the script. Make
   sure that the Uniswap X Reactor address matches the reactor you are targeting.
3. Run `npx hardhat run scripts/deploy-uniswap-x-filler.js --network NETWORK`.

## Export Runtime Bytecode

The `export-runtime-bytecode.js` script allows you to export the runtime bytecode of any executor contract for use in
SDK testing.

### Prerequisites

1. Ensure the contract is compiled: `forge build`
2. Start a local blockchain: `anvil` (or `anvil &` to run in background)

### Usage

```bash
node scripts/export-runtime-bytecode.js <ContractName> [constructorArg1] [constructorArg2] ...
```

### Example

```bash
# Export BalancerV2Executor (requires permit2 address)
node scripts/export-runtime-bytecode.js BalancerV2Executor 0x000000000022D473030F116dDEE9F6B43aC78BA3
```

### Output

The script will:

1. Deploy the contract with the provided constructor arguments to your local fork
2. Extract the runtime bytecode (including immutables)
3. Save it to `test/{ContractName}.runtime.json`

The generated JSON file contains the runtime bytecode in the format expected by the SDK and should be copied to the
appropriate SDK repository for testing. **Do not commit these files to this repository.**
