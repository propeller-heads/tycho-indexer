/** @type import('hardhat/config').HardhatUserConfig */
require("@tenderly/hardhat-tenderly");
require("@nomicfoundation/hardhat-verify");
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
            accounts: [process.env.PRIVATE_KEY],
            chainId: 1
        },
        base: {
            url: process.env.RPC_URL,
            accounts: [process.env.PRIVATE_KEY],
            chainId: 8453
        },
        unichain: {
            url: process.env.RPC_URL,
            accounts: [process.env.PRIVATE_KEY],
            chainId: 130
        }
    },

    tenderly: {
        project: "project",
        username: "tvinagre",
        privateVerification: false,
    },

    etherscan: {
        apiKey: {
          unichain: process.env.BLOCKCHAIN_EXPLORER_API_KEY,
          base: process.env.BLOCKCHAIN_EXPLORER_API_KEY,
          ethereum: process.env.BLOCKCHAIN_EXPLORER_API_KEY,
        },
        customChains: [
          {
            network: "unichain",
            chainId: 130,
            urls: {
              apiURL: "https://api.uniscan.xyz/api",
              browserURL: "https://www.uniscan.xyz/"
            }
          }
        ]
    }
};
