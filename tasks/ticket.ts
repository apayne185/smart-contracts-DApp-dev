import { task } from "hardhat/config";
import { ArgumentType } from "hardhat/types/arguments";
import fs from "fs";

function loadAddress(): string {
  try {
    return JSON.parse(fs.readFileSync("deployments/TicketOffice.json", "utf8")).address;
  } catch {
    throw new Error("Run 'npx hardhat run scripts/deploy-ticket.ts --network <network>' first.");
  }
}

const artifactPath = "artifacts/contracts/TicketOffice.sol/TicketOffice.json";
function loadAbi() {
  return JSON.parse(fs.readFileSync(artifactPath, "utf8")).abi;
}

// ── ticket:list ───────────────────────────────────────────────────────────────
task(["ticket", "list"], "List all events")
  .setInlineAction(async (_args, hre) => {
    const { ethers } = await hre.network.getOrCreate();
    const office = new ethers.Contract(loadAddress(), loadAbi(), (await ethers.getSigners())[0]);
    const ids: bigint[] = await office.allEventIds();
    if (ids.length === 0) { console.log("No events."); return; }
    console.log(`\nTicketOffice @ ${loadAddress()}\n`);
    console.log("ID   Name                  Price (ETH)   Supply  Sold  Active  Date");
    console.log("─".repeat(68));
    for (const id of ids) {
      const [, name, price, supply, sold, date, active] = await office.getEventById(id);
      const dateStr = new Date(Number(date) * 1000).toLocaleDateString();
      console.log(
        `${String(id).padEnd(5)}${name.padEnd(22)}${ethers.formatEther(price).padEnd(14)}` +
        `${String(supply).padEnd(8)}${String(sold).padEnd(6)}${String(active).padEnd(8)}${dateStr}`
      );
    }
  });

// ── ticket:buy ────────────────────────────────────────────────────────────────
task(["ticket", "buy"], "Buy one ticket for an event at face price")
  .addOption({ name: "eventId", description: "Event ID", type: ArgumentType.BIGINT, defaultValue: 1n })
  .setInlineAction(async ({ eventId }, hre) => {
    const { ethers } = await hre.network.getOrCreate();
    const [, user] = await ethers.getSigners();
    const office = new ethers.Contract(loadAddress(), loadAbi(), user);
    const [, name, price] = await office.getEventById(eventId);
    console.log(`Buying ticket for "${name}" @ ${ethers.formatEther(price)} ETH...`);
    const rc = await (await office.buyTicket(eventId, { value: price })).wait();
    const parsed = rc.logs
      .map((l: any) => { try { return office.interface.parseLog(l); } catch { return null; } })
      .find((e: any) => e?.name === "TicketPurchased");
    console.log(`Ticket #${parsed?.args.ticketId} issued. Tx: ${rc.hash}`);
  });

// ── ticket:my-tickets ─────────────────────────────────────────────────────────
task(["ticket", "my-tickets"], "List tickets owned by an address")
  .addOption({ name: "address", description: "Address to check (defaults to signer[1])", type: ArgumentType.STRING_WITHOUT_DEFAULT })
  .setInlineAction(async ({ address }, hre) => {
    const { ethers } = await hre.network.getOrCreate();
    const signers = await ethers.getSigners();
    const who = address ?? signers[1].address;
    const office = new ethers.Contract(loadAddress(), loadAbi(), signers[0]);
    const ids: bigint[] = await office.ticketsOf(who);
    if (ids.length === 0) { console.log(`${who} owns no tickets.`); return; }
    console.log(`Tickets owned by ${who}:`);
    for (const tid of ids) {
      const [, eventId] = await office.getTicket(tid);
      const [, name]    = await office.getEventById(eventId);
      const [listPrice, listed] = await office.getListing(tid);
      const tag = listed ? ` [listed @ ${ethers.formatEther(listPrice)} ETH]` : "";
      console.log(`  Ticket #${tid} — ${name}${tag}`);
    }
  });

// ── ticket:transfer ───────────────────────────────────────────────────────────
task(["ticket", "transfer"], "Transfer a ticket to another address")
  .addOption({ name: "ticketId", description: "Ticket ID",           type: ArgumentType.BIGINT, defaultValue: 1n })
  .addOption({ name: "to",       description: "Recipient address",   type: ArgumentType.STRING, defaultValue: "" })
  .setInlineAction(async ({ ticketId, to }, hre) => {
    const { ethers } = await hre.network.getOrCreate();
    const [, user] = await ethers.getSigners();
    const office = new ethers.Contract(loadAddress(), loadAbi(), user);
    await (await office.transferTicket(ticketId, to)).wait();
    console.log(`Ticket #${ticketId} transferred to ${to}`);
  });

// ── ticket:list-resale ────────────────────────────────────────────────────────
task(["ticket", "list-resale"], "List a ticket for resale")
  .addOption({ name: "ticketId", description: "Ticket ID",       type: ArgumentType.BIGINT, defaultValue: 1n })
  .addOption({ name: "price",    description: "Resale price ETH", type: ArgumentType.STRING, defaultValue: "0.03" })
  .setInlineAction(async ({ ticketId, price }, hre) => {
    const { ethers } = await hre.network.getOrCreate();
    const [, user] = await ethers.getSigners();
    const office = new ethers.Contract(loadAddress(), loadAbi(), user);
    await (await office.listForResale(ticketId, ethers.parseEther(price))).wait();
    console.log(`Ticket #${ticketId} listed at ${price} ETH`);
  });

// ── ticket:cancel-listing ─────────────────────────────────────────────────────
task(["ticket", "cancel-listing"], "Cancel a resale listing")
  .addOption({ name: "ticketId", description: "Ticket ID", type: ArgumentType.BIGINT, defaultValue: 1n })
  .setInlineAction(async ({ ticketId }, hre) => {
    const { ethers } = await hre.network.getOrCreate();
    const [, user] = await ethers.getSigners();
    const office = new ethers.Contract(loadAddress(), loadAbi(), user);
    await (await office.cancelListing(ticketId)).wait();
    console.log(`Listing for ticket #${ticketId} cancelled`);
  });

// ── ticket:buy-resale ─────────────────────────────────────────────────────────
task(["ticket", "buy-resale"], "Buy a ticket listed on the secondary market")
  .addOption({ name: "ticketId", description: "Ticket ID", type: ArgumentType.BIGINT, defaultValue: 1n })
  .setInlineAction(async ({ ticketId }, hre) => {
    const { ethers } = await hre.network.getOrCreate();
    const [, user] = await ethers.getSigners();
    const office = new ethers.Contract(loadAddress(), loadAbi(), user);
    const [price] = await office.getListing(ticketId);
    await (await office.buyResale(ticketId, { value: price })).wait();
    console.log(`Bought ticket #${ticketId} for ${ethers.formatEther(price)} ETH`);
  });

// ── ticket:create ─────────────────────────────────────────────────────────────
task(["ticket", "create"], "Admin: create a new event")
  .addOption({ name: "name",   description: "Event name",          type: ArgumentType.STRING, defaultValue: "" })
  .addOption({ name: "price",  description: "Ticket price in ETH", type: ArgumentType.STRING, defaultValue: "0.01" })
  .addOption({ name: "supply", description: "Total ticket supply", type: ArgumentType.BIGINT, defaultValue: 100n })
  .addOption({ name: "date",   description: "Event date (unix ts)", type: ArgumentType.BIGINT, defaultValue: BigInt(Math.floor(Date.now() / 1000) + 86400 * 30) })
  .setInlineAction(async ({ name, price, supply, date }, hre) => {
    const { ethers } = await hre.network.getOrCreate();
    const office = new ethers.Contract(loadAddress(), loadAbi(), (await ethers.getSigners())[0]);
    await (await office.createEvent(name, ethers.parseEther(price), supply, date)).wait();
    console.log(`Created event "${name}"`);
  });

// ── ticket:withdraw ───────────────────────────────────────────────────────────
task(["ticket", "withdraw"], "Admin: withdraw collected ETH")
  .setInlineAction(async (_args, hre) => {
    const { ethers } = await hre.network.getOrCreate();
    const admin = (await ethers.getSigners())[0];
    const office = new ethers.Contract(loadAddress(), loadAbi(), admin);
    const bal = await ethers.provider.getBalance(loadAddress());
    await (await office.withdraw()).wait();
    console.log(`Withdrew ${ethers.formatEther(bal)} ETH to ${admin.address}`);
  });
