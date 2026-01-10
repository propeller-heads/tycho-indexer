const {ethers} = require('ethers');
const fs = require('fs');
const path = require('path');

const contractName = process.argv[2];
const constructorArgs = process.argv.slice(3);

if (!contractName) {
    console.error('Usage: node export-runtime-bytecode.js <ContractName> [constructorArg1] [constructorArg2] ...');
    console.error('Example: node export-runtime-bytecode.js BalancerV2Executor 0x000000000022D473030F116dDEE9F6B43aC78BA3');
    process.exit(1);
}

async function exportRuntimeBytecode() {
    try {
        const artifactPath = path.join(__dirname, '..', 'out', `${contractName}.sol`, `${contractName}.json`);

        if (!fs.existsSync(artifactPath)) {
            console.error(`Contract artifact not found at: ${artifactPath}`);
            console.error('Make sure the contract is compiled with: forge build');
            process.exit(1);
        }

        const artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));

        // Create a provider (using a dummy one since we're just deploying locally)
        const provider = new ethers.providers.JsonRpcProvider('http://127.0.0.1:8545');

        // Create a wallet with a dummy private key (for local deployment)
        const wallet = new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider);

        const contractFactory = new ethers.ContractFactory(
            artifact.abi,
            artifact.bytecode.object,
            wallet
        );

        console.log(`Deploying ${contractName}...`);
        console.log(`Constructor args: [${constructorArgs.join(', ')}]`);

        const contract = await contractFactory.deploy(...constructorArgs);
        await contract.deployed();

        const contractAddress = contract.address;
        console.log(`Contract deployed at: ${contractAddress}`);

        const runtimeBytecode = await provider.getCode(contractAddress);
        console.log(`Runtime bytecode length: ${runtimeBytecode.length} characters`);

        const output = {
            runtimeBytecode: runtimeBytecode
        };

        const outputPath = path.join(__dirname, '..', 'test', `${contractName}.runtime.json`);
        fs.writeFileSync(outputPath, JSON.stringify(output, null, 2));

        console.log(`Runtime bytecode exported to: ${outputPath}`);

    } catch (error) {
        console.error('Error:', error.message);
        process.exit(1);
    }
}

exportRuntimeBytecode();