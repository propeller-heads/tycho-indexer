/** @type import('hardhat/config').HardhatUserConfig */
require("@tenderly/hardhat-tenderly");
require("@nomiclabs/hardhat-ethers");
require("@nomicfoundation/hardhat-foundry");

module.exports = {
    solidity: {
        version: "0.8.26",
        settings: {
            evmVersion: "cancun",
            viaIR: true,
            optimizer: {
                enabled: true,
                runs: 1000,
            },
        },
    },

    networks: {
        tenderly_ethereum: {
            url: process.env.RPC_URL,
            accounts: [process.env.PRIVATE_KEY]
        },
        tenderly_base: {
            url: process.env.RPC_URL,
            accounts: [process.env.PRIVATE_KEY]
        },
        ethereum: {
            url: process.env.RPC_URL,
            accounts: [process.env.PRIVATE_KEY]
        },
        base: {
            url: process.env.RPC_URL,
            accounts: [process.env.PRIVATE_KEY]
        }
    },

    tenderly: {
        project: "project",
        username: "tvinagre",
        privateVerification: true,
    },
};
