import { network } from "hardhat";
import fs from "fs";

const { ethers, networkName } = await network.connect();

console.log(`Deploying VendingMachine to ${networkName}...`);

const contract = await ethers.deployContract("VendingMachine");
await contract.waitForDeployment();

const address = await contract.getAddress();
console.log("Contract deployed to:", address);

// seed catalog so dApp has products to show
const seed = [
  { name: "Cola",price: ethers.parseEther("0.01"), stock: 10 },
  { name: "Chips", price: ethers.parseEther("0.005"), stock: 20 },
  { name: "Chocolate", price: ethers.parseEther("0.008"), stock: 15 },
];
for (const p of seed) {
  const tx = await contract.addProduct(p.name, p.price, p.stock);
  await tx.wait();
  console.log(`  added ${p.name}`);
}



// save deployed contract address
fs.writeFileSync("deployed-address.txt", address);   



// save ABI for python
const artifactPath =
  "./artifacts/contracts/VendingMachine.sol/VendingMachine.json";
const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));

fs.writeFileSync(
  "VendingMachine.abi.json",
  JSON.stringify(artifact.abi, null, 2)
);

console.log("Saved deployed-address.txt");
console.log("Saved VendingMachine.abi.json");
