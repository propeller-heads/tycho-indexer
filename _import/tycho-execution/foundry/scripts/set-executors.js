require('dotenv').config();
const {ethers} = require("hardhat");
const path = require('path');
const fs = require('fs');
const hre = require("hardhat");
const prompt = require('prompt-sync')();

async function main() {
    const network = hre.network.name;
    const routerAddress = process.env.ROUTER_ADDRESS;
    console.log(`Setting executors on TychoRouter at ${routerAddress} on ${network}`);

    const [deployer] = await ethers.getSigners();
    console.log(`Setting executors with account: ${deployer.address}`);
    console.log(`Account balance: ${ethers.utils.formatEther(await deployer.getBalance())} ETH`);

    const TychoRouter = await ethers.getContractFactory("TychoRouter");
    const router = TychoRouter.attach(routerAddress);

    const executorsFilePath = path.join(__dirname, "../../config/executor_addresses.json");
    const executors = Object.entries(JSON.parse(fs.readFileSync(executorsFilePath, "utf8"))[network]);


    // Filter out executors that are already set
    const executorsToSet = [];
    for (const [name, executor] of executors) {
        const isExecutorSet = await router.executors(executor);
        if (!isExecutorSet) {
            executorsToSet.push({name: name, executor: executor});
        }
    }

    if (executorsToSet.length === 0) {
        console.log("All executors are already set. No changes needed.");
        return;
    }

    console.log(`The following ${executorsToSet.length} executor(s) will be set:`);
    executorsToSet.forEach(executor => {
        console.log(`Name: ${executor.name}`);
        console.log(`Address: ${executor.executor}`);
        console.log("———");
    });

    const userConfirmation = prompt("Do you want to proceed with setting these executors? (yes/no): ");
    if (userConfirmation.toLowerCase() !== 'yes') {
        console.log("Operation cancelled by user.");
        return;
    }

    // Set executors
    const executorAddresses = executorsToSet.map(executor => executor.executor);
    const tx = await router.setExecutors(executorAddresses, {
        gasLimit: 300000 // should be around 50k per executor
    });
    await tx.wait(); // Wait for the transaction to be mined
    console.log(`Executors set at transaction: ${tx.hash}`);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("Error setting executors:", error);
        process.exit(1);
    });