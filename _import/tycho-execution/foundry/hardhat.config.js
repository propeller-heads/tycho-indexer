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
        },
    },

    networks: {
        tenderly: {
            url: process.env.TENDERLY_RPC_URL,
            accounts: [process.env.PRIVATE_KEY]
        }
    },

    tenderly: {
        project: "project",
        username: "tvinagre",
        privateVerification: true,
    },
};
