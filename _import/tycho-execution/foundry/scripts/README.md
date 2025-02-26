# How to deploy

- Install dependencies `npm install`
- `cd foundry`

## Deploy on a Tenderly fork

1. Make a new [fork](https://dashboard.tenderly.co/) in tenderly dashboard.
2. Set the following environment variables:

```
export RPC_URL=<fork-rpc-from-tenderly>
export DEPLOY_WALLET=<wallet-address>
export PRIVATE_KEY=<private-key>
```

3. Fund wallet: `npx hardhat run scripts/fund-wallet-tenderly-fork.js --network tenderly`

## Deploy on mainnet

1. Set the following environment variables:

```
export RPC_URL=<mainnet-rpc-url>
export DEPLOY_WALLET=<wallet-address>
export PRIVATE_KEY=<private-key>
```

Make sure to run `unset HISTFILE` in your terminal before setting the private key. This will prevent the private key
from being stored in the shell history.

## Deploy Tycho Router

1. Deploy router: `npx hardhat run scripts/deploy-router.js --network tenderly/mainnet`
2. Define the accounts to grant roles to in `scripts/roles.json`
3. Export the router address to the environment variable `export ROUTER=<router-address>`
4. Grant roles: `npx hardhat run scripts/set-roles.js --network tenderly/mainnet`
5. Set executors: `npx hardhat run scripts/set-executors.js --network tenderly/mainnet`. Make sure you change the
   DEPLOY_WALLET
   to the executor deployer wallet. If you need to deploy executors, follow the instructions below.

### Deploy executors

1. In `scripts/deploy-executors.js` define the executors to be deployed
2. Deploy executors: `npx hardhat run scripts/deploy-executors.js --network tenderly/mainnet`
3. Fill in the executor addresses in `config/executor_addresses.json`. Note that the naming there needs to match the one
   from tycho-indexer.
