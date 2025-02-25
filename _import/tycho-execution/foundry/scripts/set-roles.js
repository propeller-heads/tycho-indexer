require('dotenv').config();
const {ethers} = require("hardhat");
const path = require('path');
const fs = require('fs');
const hre = require("hardhat");

async function main() {
    const network = hre.network.name;
    const routerAddress = process.env.ROUTER_ADDRESS;
    console.log(`Setting roles on TychoRouter at ${routerAddress} on ${network}`);

    const [deployer] = await ethers.getSigners();
    console.log(`Setting roles with account: ${deployer.address}`);
    console.log(`Account balance: ${ethers.utils.formatEther(await deployer.getBalance())} ETH`);
    const TychoRouter = await ethers.getContractFactory("TychoRouter");
    const router = TychoRouter.attach(routerAddress);

    const rolesFilePath = path.join(__dirname, "roles.json");
    const rolesDict = JSON.parse(fs.readFileSync(rolesFilePath, "utf8"));

    const roles = {
        EXECUTOR_SETTER_ROLE: "0x6a1dd52dcad5bd732e45b6af4e7344fa284e2d7d4b23b5b09cb55d36b0685c87",
        FEE_SETTER_ROLE: "0xe6ad9a47fbda1dc18de1eb5eeb7d935e5e81b4748f3cfc61e233e64f88182060",
        PAUSER_ROLE: "0x65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a",
        UNPAUSER_ROLE: "0x427da25fe773164f88948d3e215c94b6554e2ed5e5f203a821c9f2f6131cf75a",
        FUND_RESCUER_ROLE: "0x912e45d663a6f4cc1d0491d8f046e06c616f40352565ea1cdb86a0e1aaefa41b"
    };

    // Iterate through roles and grant them to the corresponding addresses
    for (const [roleName, roleHash] of Object.entries(roles)) {
        const addresses = rolesDict[network][roleName];
        if (addresses && addresses.length > 0) {
            console.log(`Granting ${roleName} to the following addresses:`, addresses);
            const tx = await router.batchGrantRole(roleHash, addresses);
            await tx.wait(); // Wait for the transaction to be mined
            console.log(`Role ${roleName} granted at transaction: ${tx.hash}`);
        } else {
            console.log(`No addresses found for role ${roleName}`);
        }
    }
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("Error setting roles:", error);
        process.exit(1);
    });