import { network } from "hardhat";
import fs from "fs";

const { ethers, networkName } = await network.connect();

console.log(`Deploying TicketOffice to ${networkName}...`);

const contract = await ethers.deployContract("TicketOffice");
await contract.waitForDeployment();
const address = await contract.getAddress();
console.log("Contract deployed to:", address);

// Seed 2 events so the dApp has something to show.
const nowSec = Math.floor(Date.now() / 1000);
const seed = [
  { name: "Rock Concert", price: ethers.parseEther("0.02"), supply: 5,  date: nowSec + 14 * 86400 },
  { name: "Tech Meetup",  price: ethers.parseEther("0.01"), supply: 10, date: nowSec + 7  * 86400 },
];
for (const e of seed) {
  const tx = await contract.createEvent(e.name, e.price, e.supply, e.date);
  await tx.wait();
  console.log(`  created event: ${e.name}`);
}

fs.writeFileSync("deployed-address.txt", address);

const artifactPath = "./artifacts/contracts/TicketOffice.sol/TicketOffice.json";
const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
fs.writeFileSync("TicketOffice.abi.json", JSON.stringify(artifact.abi, null, 2));

console.log("Saved deployed-address.txt");
console.log("Saved TicketOffice.abi.json");
