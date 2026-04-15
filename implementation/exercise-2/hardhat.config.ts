import hardhatToolboxMochaEthersPlugin from "@nomicfoundation/hardhat-toolbox-mocha-ethers";
import { configVariable, defineConfig } from "hardhat/config";

export default defineConfig({
  plugins: [hardhatToolboxMochaEthersPlugin],
  solidity: {
    profiles: {
      default:{ version: "0.8.24" },
      production: {
        version: "0.8.24",
        settings: { optimizer: { enabled: true, runs: 200 } },
      },
    },
  },
  paths: {
    sources: "./contracts",
    tests:"./tests",
  },
  networks: {
    ganache: {
      type: "http",
      url: "http://127.0.0.1:8545",
      chainId: 1337,
    },
    hardhatMainnet: { type: "edr-simulated", chainType: "l1" },
    hardhatOp: { type: "edr-simulated", chainType: "op" },
    sepolia: {
      type: "http",
      chainType: "l1",
      url: configVariable("SEPOLIA_RPC_URL"),
      accounts: [configVariable("SEPOLIA_PRIVATE_KEY")],
    },
  },
});
