require('dotenv').config();
const {ethers} = require("hardhat");
const hre = require("hardhat");

// Comment out the executors you don't want to deploy
const executors_to_deploy = {
    "ethereum": [
        // USV2 - Args: Factory, Pool Init Code Hash, Permit2, Fee BPS
        {
            exchange: "UniswapV2Executor", args: [
                "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
                "0x96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f",
                "0x000000000022D473030F116dDEE9F6B43aC78BA3",
                30
            ]
        },
        // SUSHISWAP - Args: Factory, Pool Init Code Hash, Fee BPS, Permit2, Fee BPS
        {
            exchange: "UniswapV2Executor", args: [
                "0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac",
                "0xe18a34eb0e04b04f7a0ac29a6e80748dca96319b42c54d679cb821dca90c6303",
                "0x000000000022D473030F116dDEE9F6B43aC78BA3",
                30
            ]
        },
        // PANCAKESWAP V2 - Args: Factory, Pool Init Code Hash, Permit2, Fee BPS
        {
            exchange: "UniswapV2Executor", args: [
                "0x1097053Fd2ea711dad45caCcc45EfF7548fCB362",
                "0x57224589c67f3f30a6b0d7a1b54cf3153ab84563bc609ef41dfb34f8b2974d2d",
                "0x000000000022D473030F116dDEE9F6B43aC78BA3",
                25
            ]
        },
        // USV3 -Args: Factory, Pool Init Code Hash, Permit2
        {
            exchange: "UniswapV3Executor", args: [
                "0x1F98431c8aD98523631AE4a59f267346ea31F984",
                "0xe34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54",
                "0x000000000022D473030F116dDEE9F6B43aC78BA3"
            ]
        },
        // PANCAKESWAP V3 - Args: Deployer, Pool Init Code Hash, Permit2
        {
            exchange: "UniswapV3Executor", args: [
                "0x41ff9AA7e16B8B1a8a8dc4f0eFacd93D02d071c9",
                "0x6ce8eb472fa82df5469c6ab6d485f17c3ad13c8cd7af59b3d4a8026c5ce0f7e2",
                "0x000000000022D473030F116dDEE9F6B43aC78BA3"
            ]
        },
        // Args: Pool manager
        {
            exchange: "UniswapV4Executor", args: [
                "0x000000000004444c5dc75cB358380D2e3dE08A90",
                "0x000000000022D473030F116dDEE9F6B43aC78BA3"
            ]
        },
        // Args: Permit2
        {exchange: "BalancerV2Executor", args: ["0x000000000022D473030F116dDEE9F6B43aC78BA3"]},
        // Args: Ekubo core contract, mev resist, Permit2
        {
            exchange: "EkuboExecutor", args: [
                "0xe0e0e08A6A4b9Dc7bD67BCB7aadE5cF48157d444",
                "0x553a2EFc570c9e104942cEC6aC1c18118e54C091",
                "0x000000000022D473030F116dDEE9F6B43aC78BA3"
            ]
        },
        // Args: ETH address in curve pools, Permit2
        {
            exchange: "CurveExecutor", args: [
                "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",
                "0x000000000022D473030F116dDEE9F6B43aC78BA3"
            ]
        },
        // Args: factory, permit2
        {
            exchange: "MaverickV2Executor", args: [
                "0x0A7e848Aca42d879EF06507Fca0E7b33A0a63c1e",
                "0x000000000022D473030F116dDEE9F6B43aC78BA3"
            ]
        },
    ],
    "base": [
        // Args: Factory, Pool Init Code Hash, Permit2, Fee BPS
        {
            exchange: "UniswapV2Executor", args: [
                "0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6",
                "0x96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f",
                "0x000000000022D473030F116dDEE9F6B43aC78BA3",
                30
            ]
        },
        // PANCAKESWAP V2 - Args: Factory, Pool Init Code Hash, Permit2, Fee BPS
        {
            exchange: "UniswapV2Executor", args: [
                "0x1097053Fd2ea711dad45caCcc45EfF7548fCB362",
                "0x57224589c67f3f30a6b0d7a1b54cf3153ab84563bc609ef41dfb34f8b2974d2d",
                "0x000000000022D473030F116dDEE9F6B43aC78BA3",
                25
            ]
        },
        // USV3 - Args: Factory, Pool Init Code Hash, Permit2
        {
            exchange: "UniswapV3Executor", args: [
                "0x33128a8fC17869897dcE68Ed026d694621f6FDfD",
                "0xe34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54",
                "0x000000000022D473030F116dDEE9F6B43aC78BA3"
            ]
        },
        // Args: Pool manager, Permit2
        {
            exchange: "UniswapV4Executor", args: [
                "0x498581ff718922c3f8e6a244956af099b2652b2b",
                "0x000000000022D473030F116dDEE9F6B43aC78BA3"
            ]
        },
    ],
    "unichain": [
        // Args: Factory, Pool Init Code Hash, Permit2, Fee BPS
        {
            exchange: "UniswapV2Executor", args: [
                "0x1f98400000000000000000000000000000000002",
                "0x96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f",
                "0x000000000022D473030F116dDEE9F6B43aC78BA3",
                30
            ]
        },
        // USV3 - Args: Factory, Pool Init Code Hash, Permit2
        {
            exchange: "UniswapV3Executor", args: [
                "0x1f98400000000000000000000000000000000003",
                "0xe34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54",
                "0x000000000022D473030F116dDEE9F6B43aC78BA3"
            ]
        },
        // Args: Pool manager, Permit2
        {
            exchange: "UniswapV4Executor", args: [
                "0x1f98400000000000000000000000000000000004",
                "0x000000000022D473030F116dDEE9F6B43aC78BA3"
            ]
        },
    ],
}

async function main() {
    const network = hre.network.name;
    console.log(`Deploying executors to ${network}`);

    const [deployer] = await ethers.getSigners();
    console.log(`Deploying with account: ${deployer.address}`);
    console.log(`Account balance: ${ethers.utils.formatEther(await deployer.getBalance())} ETH`);

    for (const executor of executors_to_deploy[network]) {
        const {exchange, args} = executor;
        const Executor = await ethers.getContractFactory(exchange);
        const deployedExecutor = await Executor.deploy(...args);
        await deployedExecutor.deployed();
        console.log(`${exchange} deployed to: ${deployedExecutor.address}`);

        // Verify on Tenderly
        try {
            await hre.tenderly.verify({
                name: exchange,
                address: deployedExecutor.address,
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
                address: deployedExecutor.address,
                constructorArguments: args,
            });
            console.log(`${exchange} verified successfully on blockchain explorer!`);
        } catch (error) {
            console.error(`Error during blockchain explorer verification:`, error);
        }
    }
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("Deployment failed:", error);
        process.exit(1);
    });