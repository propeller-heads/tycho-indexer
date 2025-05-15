require('dotenv').config();
const {ethers} = require("hardhat");
const hre = require("hardhat");
const prompt = require('prompt-sync')();

async function main() {
    const network = hre.network.name;
    const routerAddress = process.env.ROUTER_ADDRESS;
    console.log(`Removing executors on TychoRouter at ${routerAddress} on ${network}`);

    const [deployer] = await ethers.getSigners();
    console.log(`Removing executors with account: ${deployer.address}`);
    console.log(`Account balance: ${ethers.utils.formatEther(await deployer.getBalance())} ETH`);

    const TychoRouter = await ethers.getContractFactory("TychoRouter");
    const router = TychoRouter.attach(routerAddress);

    const executorAddress = prompt("Enter executor address to remove: ");

    if (!executorAddress) {
        console.error("Please provide the executorAddress as an argument.");
        process.exit(1);
    }

    // Remove executor
    const tx = await router.removeExecutor(executorAddress, {
        gasLimit: 50000
    });
    await tx.wait(); // Wait for the transaction to be mined
    console.log(`Executor removed at transaction: ${tx.hash}`);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("Error removing executor:", error);
        process.exit(1);
    });