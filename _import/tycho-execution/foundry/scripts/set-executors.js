require('dotenv').config();
const {ethers} = require("hardhat");
const fs = require('fs');
const path = require('path');
const {proposeOrSendTransaction} = require("./utils");
const prompt = require('prompt-sync')();

async function main() {
    const network = hre.network.name;
    const routerAddress = process.env.ROUTER_ADDRESS;
    const safeAddress = process.env.SAFE_ADDRESS;
    if (!routerAddress) {
        throw new Error("Missing ROUTER_ADDRESS");
    }

    console.log(`Setting executors on TychoRouter at ${routerAddress} on ${network}`);

    const [signer] = await ethers.getSigners();
    const balance = await signer.getBalance();

    console.log(`Using signer: ${signer.address}`);
    console.log(`Account balance: ${ethers.utils.formatEther(balance)} ETH`);

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

    const executorAddresses = executorsToSet.map(({executor}) => executor);
    const txData = {
        to: router.address,
        data: router.interface.encodeFunctionData("setExecutors", [executorAddresses]),
        value: "0",
        gasLimit: 300000
    };

    const txHash = await proposeOrSendTransaction(safeAddress, txData, signer, "setExecutors");
    console.log(`TX hash: ${txHash}`);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("Error setting executors:", error);
        process.exit(1);
    });