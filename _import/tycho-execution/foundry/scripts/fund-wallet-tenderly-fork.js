require("dotenv").config();
const {ethers} = require("hardhat");

const RPC_URL = process.env.RPC_URL;
const DEPLOY_WALLET = process.env.DEPLOY_WALLET;

async function main() {
    if (!RPC_URL || !DEPLOY_WALLET) {
        console.error("Missing RPC_URL or DEPLOY_WALLET in environment variables.");
        process.exit(1);
    }

    const provider = ethers.provider; // Use Hardhat's provider
    const balanceHex = ethers.utils.hexValue(ethers.utils.parseUnits("10", "ether")); // Convert 10 ETH to hex
    console.log(`Funding wallet ${DEPLOY_WALLET} with 10 ETH on Tenderly...`);

    try {
        const result = await provider.send("tenderly_setBalance", [[DEPLOY_WALLET], balanceHex]);
        console.log(`Successfully funded wallet: ${DEPLOY_WALLET}`);
        console.log(result);
    } catch (error) {
        console.error("Error funding wallet:", error);
    }
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});