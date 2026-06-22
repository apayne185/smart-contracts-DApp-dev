import { network } from "hardhat";
import fs from "fs";
import path from "path";

const { ethers, networkName } = await network.connect();

console.log(`Deploying VendingMachine to ${networkName}...`);

const contract = await ethers.deployContract("VendingMachine");
await contract.waitForDeployment();

const address = await contract.getAddress();
console.log(`Deployed to: ${address}`);

// Seed initial catalog
const catalog = [
  { name: "Cola",      price: ethers.parseEther("0.01"),  stock: 10 },
  { name: "Chips",     price: ethers.parseEther("0.005"), stock: 20 },
  { name: "Chocolate", price: ethers.parseEther("0.008"), stock: 15 },
];
for (const p of catalog) {
  await (await contract.addProduct(p.name, p.price, p.stock)).wait();
  console.log(`  + ${p.name} @ ${ethers.formatEther(p.price)} ETH (stock: ${p.stock})`);
}

// Save deployment info for interaction scripts
const deployment = { address, network: networkName, deployedAt: new Date().toISOString() };
fs.mkdirSync("deployments", { recursive: true });
fs.writeFileSync(
  path.join("deployments", "VendingMachine.json"),
  JSON.stringify(deployment, null, 2)
);
console.log(`\nSaved deployments/VendingMachine.json`);
