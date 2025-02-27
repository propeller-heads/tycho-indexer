require('dotenv').config();
const {ethers} = require("hardhat");
const hre = require("hardhat");

// Comment out the executors you don't want to deploy
const executors_to_deploy = [
    {exchange: "UniswapV2Executor", args: []},
    // {exchange: "UniswapV3Executor", args: ["0x1F98431c8aD98523631AE4a59f267346ea31F984"]},
    // {exchange: "UniswapV4Executor", args: ["0x000000000004444c5dc75cB358380D2e3dE08A90"]},
    // {exchange: "BalancerV2Executor", args: []},
]

async function main() {
    const network = hre.network.name;
    console.log(`Deploying executors to ${network}`);

    const [deployer] = await ethers.getSigners();
    console.log(`Deploying with account: ${deployer.address}`);
    console.log(`Account balance: ${ethers.utils.formatEther(await deployer.getBalance())} ETH`);

    for (const executor of executors_to_deploy) {
        const {exchange, args} = executor;
        const Executor = await ethers.getContractFactory(exchange);
        const deployedExecutor = await Executor.deploy(...args);
        await deployedExecutor.deployed();
        console.log(`${exchange} deployed to: ${deployedExecutor.address}`);

        // Verify on Tenderly
        try {
            await hre.tenderly.verify({
                name: exchange,
                address: address,
            });
            console.log("Contract verified successfully on Tenderly");
        } catch (error) {
            console.error("Error during contract verification:", error);
        }

        console.log("Waiting for 1 minute before verifying the contract...");
        await new Promise(resolve => setTimeout(resolve, 60000));
        // Verify on Etherscan
        try {
            await hre.run("verify:verify", {
                address: address,
                constructorArguments: args,
            });
            console.log(`${exchange} verified successfully on Etherscan!`);
        } catch (error) {
            console.error(`Error during Etherscan verification:`, error);
        }
    }
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("Deployment failed:", error);
        process.exit(1);
    });