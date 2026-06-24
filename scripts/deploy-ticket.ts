import { network } from "hardhat";
import fs from "fs";
import path from "path";

const { ethers, networkName } = await network.connect();

console.log(`Deploying TicketOffice to ${networkName}...`);

const contract = await ethers.deployContract("TicketOffice");
await contract.waitForDeployment();

const address = await contract.getAddress();
console.log(`Deployed to: ${address}`);

// Seed initial events (dates 7 and 14 days from now)
const nowSec = Math.floor(Date.now() / 1000);
const events = [
  { name: "Rock Concert", price: ethers.parseEther("0.02"), supply: 5,  date: nowSec + 14 * 86400 },
  { name: "Tech Meetup",  price: ethers.parseEther("0.01"), supply: 10, date: nowSec + 7  * 86400 },
];
for (const e of events) {
  await (await contract.createEvent(e.name, e.price, e.supply, e.date)).wait();
  const dateStr = new Date(e.date * 1000).toLocaleDateString();
  console.log(`  + ${e.name} @ ${ethers.formatEther(e.price)} ETH (supply: ${e.supply}, date: ${dateStr})`);
}

const deployment = { address, network: networkName, deployedAt: new Date().toISOString() };
fs.mkdirSync("deployments", { recursive: true });
fs.writeFileSync(
  path.join("deployments", "TicketOffice.json"),
  JSON.stringify(deployment, null, 2)
);
console.log(`\nSaved deployments/TicketOffice.json`);
