require('dotenv').config();
const {ethers} = require("hardhat");
const hre = require("hardhat");

// Comment out the executors you don't want to deploy
const executors_to_deploy = {
  "ethereum":[
    // USV2 - Args: Factory, Pool Init Code Hash
    {exchange: "UniswapV2Executor", args: [
      "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
      "0x96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f"
      ]},
    // SUSHISWAP - Args: Factory, Pool Init Code Hash
    {exchange: "UniswapV2Executor", args: [
      "0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac",
      "0xe18a34eb0e04b04f7a0ac29a6e80748dca96319b42c54d679cb821dca90c6303"
      ]},
    // PANCAKESWAP V2 - Args: Factory, Pool Init Code Hash
    {exchange: "UniswapV2Executor", args: [
      "0x1097053Fd2ea711dad45caCcc45EfF7548fCB362",
      "0x57224589c67f3f30a6b0d7a1b54cf3153ab84563bc609ef41dfb34f8b2974d2d"
      ]},
    // USV3 -Args: Factory, Pool Init Code Hash
    {exchange: "UniswapV3Executor", args: [
      "0x1F98431c8aD98523631AE4a59f267346ea31F984",
      "0xe34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54"
    ]},
    // Args: Pool manager
    {exchange: "UniswapV4Executor", args: ["0x000000000004444c5dc75cB358380D2e3dE08A90"]},
    {exchange: "BalancerV2Executor", args: []},
  ],
  "base":[
    // Args: Factory, Pool Init Code Hash
    {exchange: "UniswapV2Executor", args: [
      "0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6",
      "0x96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f"
      ]},
    // SUSHISWAP V2 - Args: Factory, Pool Init Code Hash
    {exchange: "UniswapV2Executor", args: [
      "0x71524B4f93c58fcbF659783284E38825f0622859",
      "0xe18a34eb0e04b04f7a0ac29a6e80748dca96319b42c54d679cb821dca90c6303"
      ]},
    // PANCAKESWAP V2 - Args: Factory, Pool Init Code Hash
    {exchange: "UniswapV2Executor", args: [
      "0x02a84c1b3BBD7401a5f7fa98a384EBC70bB5749E",
      "0x57224589c67f3f30a6b0d7a1b54cf3153ab84563bc609ef41dfb34f8b2974d2d"
      ]},
    // USV3 - Args: Factory, Pool Init Code Hash
    {exchange: "UniswapV3Executor", args: [
      "0x33128a8fC17869897dcE68Ed026d694621f6FDfD",
      "0xe34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54"
    ]},
    // Args: Pool manager
    {exchange: "UniswapV4Executor", args: ["0x498581ff718922c3f8e6a244956af099b2652b2b"]},
    {exchange: "BalancerV2Executor", args: []},
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