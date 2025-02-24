# How to deploy

- Install dependencies `npm install`

## Deploy on Tenderly fork

1. Make a new [fork](https://dashboard.tenderly.co/) in tenderly dashboard.
2. Set the following environment variables:

```
export TENDERLY_RPC_URL=<fork-rpc-from-tenderly>
export DEPLOY_WALLET=<wallet-address>
export PRIVATE_KEY=<private-key>
```

3. Fund wallet: `npx hardhat run scripts/fund-wallet-tenderly-fork.js --network tenderly`
4. Deploy router: `npx hardhat run scripts/deploy-router.js --network tenderly`
5. Define the accounts to grant roles to in `scripts/roles.json`
6. Export the router address to the environment variable `export ROUTER=<router-address>`
7. Grant roles: `npx hardhat run scripts/set-roles.js --network tenderly`
