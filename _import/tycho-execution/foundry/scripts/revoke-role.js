require('dotenv').config();
const {ethers} = require("hardhat");
const path = require('path');
const fs = require('fs');
const hre = require("hardhat");
const {proposeOrSendTransaction} = require("./utils");
const prompt = require('prompt-sync')();

async function main() {
    const network = hre.network.name;
    const routerAddress = process.env.ROUTER_ADDRESS;
    const safeAddress = process.env.SAFE_ADDRESS;
    if (!routerAddress) {
        throw new Error("Missing ROUTER_ADDRESS");
    }

    console.log(`Revoking role on TychoRouter at ${routerAddress} on ${network}`);

    const [signer] = await ethers.getSigners();
    console.log(`Setting roles with account: ${signer.address}`);
    console.log(`Account balance: ${ethers.utils.formatEther(await signer.getBalance())} ETH`);
    const TychoRouter = await ethers.getContractFactory("TychoRouter");
    const router = TychoRouter.attach(routerAddress);

    const roleHash = prompt("Enter role hash to be removed: ");
    const address = prompt("Enter the address to remove: ");


    if (!roleHash || !address) {
        console.error("Please provide the executorAddress as an argument.");
        process.exit(1);
    }

    console.log(`Revoking ${roleHash} to the following address:`, address);

    const txData = {
        to: router.address,
        data: router.interface.encodeFunctionData("revokeRole", [roleHash, address]),
        value: "0",
    };

    const txHash = await proposeOrSendTransaction(safeAddress, txData, signer, "revokeRole");
    console.log(`TX hash: ${txHash}`);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("Error setting roles:", error);
        process.exit(1);
    });