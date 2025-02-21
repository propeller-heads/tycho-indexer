/** @type import('hardhat/config').HardhatUserConfig */
require("@nomiclabs/hardhat-ethers");
require("@nomicfoundation/hardhat-foundry");
// require("@tenderly/hardhat-tenderly");

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
