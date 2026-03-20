require('dotenv').config();
const {ethers} = require("hardhat");
const hre = require("hardhat");
const roles = require("./roles.json");

const ROLE_HASHES = {
    EXECUTOR_SETTER_ROLE: "0x6a1dd52dcad5bd732e45b6af4e7344fa284e2d7d4b23b5b09cb55d36b0685c87",
    PAUSER_ROLE: "0x65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a",
    UNPAUSER_ROLE: "0x427da25fe773164f88948d3e215c94b6554e2ed5e5f203a821c9f2f6131cf75a",
    ROUTER_FEE_SETTER: "0x9939157be7760e9462f1d5a0dcad88b616ddc64138e317108b40b1cf55601348",
};

async function grantRoleOnContract(contract, contractLabel, roleName, roleHash, addresses) {
    // First address already has the role from constructor; grant to the rest
    for (let i = 1; i < addresses.length; i++) {
        console.log(`Granting ${roleName} to ${addresses[i]} on ${contractLabel}...`);
        const tx = await contract.grantRole(roleHash, addresses[i]);
        await tx.wait();
        console.log(`Granted ${roleName} to ${addresses[i]} on ${contractLabel}`);
    }
}

async function main() {
    const network = hre.network.name;
    const routerAddress = process.env.ROUTER_ADDRESS;
    const feeCalculatorAddress = process.env.FEE_CALCULATOR;
    const roleName = process.env.ROLE_NAME;
    const granterPk = process.env.GRANTER_PK;

    if (!routerAddress) {
        throw new Error("Missing ROUTER_ADDRESS env var");
    }
    if (!roleName || !ROLE_HASHES[roleName]) {
        throw new Error(
            `Missing or invalid ROLE_NAME env var. Valid values: ${Object.keys(ROLE_HASHES).join(", ")}`
        );
    }
    if (roleName === "ROUTER_FEE_SETTER" && !feeCalculatorAddress) {
        throw new Error("Missing FEE_CALCULATOR env var (required for ROUTER_FEE_SETTER)");
    }
    if (!granterPk) {
        throw new Error("Missing GRANTER_PK env var");
    }

    const baseNetwork = network.replace(/^tenderly_/, "");
    if (!roles[baseNetwork]) {
        throw new Error(`No roles defined for network "${baseNetwork}" in roles.json`);
    }

    const addresses = roles[baseNetwork][roleName];
    if (!addresses || addresses.length < 2) {
        console.log(`No additional addresses to grant for ${roleName} on ${baseNetwork}`);
        return;
    }

    const granter = new ethers.Wallet(granterPk, ethers.provider);
    console.log(`Setting ${roleName} on ${network}`);
    console.log(`Granter: ${granter.address}`);
    console.log(`Granter balance: ${ethers.utils.formatEther(await granter.getBalance())} ETH`);

    if (granter.address.toLowerCase() !== addresses[0].toLowerCase()) {
        throw new Error(
            `Granter address ${granter.address} does not match first address in roles.json (${addresses[0]})`
        );
    }

    const roleHash = ROLE_HASHES[roleName];

    const TychoRouter = await ethers.getContractFactory("TychoRouter");
    const router = TychoRouter.attach(routerAddress).connect(granter);
    console.log(`TychoRouter at ${routerAddress}`);
    await grantRoleOnContract(router, "TychoRouter", roleName, roleHash, addresses);

    if (roleName === "ROUTER_FEE_SETTER") {
        const FeeCalculator = await ethers.getContractFactory("FeeCalculator");
        const feeCalculator = FeeCalculator.attach(feeCalculatorAddress).connect(granter);
        console.log(`FeeCalculator at ${feeCalculatorAddress}`);
        await grantRoleOnContract(feeCalculator, "FeeCalculator", roleName, roleHash, addresses);
    }

    console.log(`Done. ${roleName} granted to ${addresses.length - 1} additional address(es).`);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("Error setting roles:", error);
        process.exit(1);
    });