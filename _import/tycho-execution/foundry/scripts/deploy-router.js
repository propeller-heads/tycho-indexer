require('dotenv').config();
const {ethers} = require("hardhat");
const hre = require("hardhat");

async function main() {
    const network = hre.network.name;
    const permit2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
    const weth = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";

    console.log(`Deploying TychoRouter to ${network} with:`);
    console.log(`- permit2: ${permit2}`);
    console.log(`- weth: ${weth}`);

    const [deployer] = await ethers.getSigners();
    console.log(`Deploying with account: ${deployer.address}`);
    console.log(`Account balance: ${ethers.utils.formatEther(await deployer.getBalance())} ETH`);

    const TychoRouter = await ethers.getContractFactory("TychoRouter");
    const router = await TychoRouter.deploy(permit2, weth);

    await router.deployed();
    console.log(`TychoRouter deployed to: ${router.address}`);

    try {
        console.log("Verifying contract on Tenderly...");
        await hre.tenderly.verify({
            name: "TychoRouter",
            address: router.address,
        });
        console.log("Contract verified successfully on Tenderly");
    } catch (error) {
        console.error("Error during contract verification:", error);
    }
}

// Execute deployment
main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("Deployment failed:", error);
        process.exit(1);
    });