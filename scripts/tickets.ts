/**
 * TicketOffice CLI
 *
 * Usage:
 *   npx hardhat run scripts/tickets.ts --network ganache -- <command> [args]
 *
 * Commands:
 *   list-events                             List all events
 *   buy   <event-id>                        Buy 1 ticket for event <id>
 *   my-tickets [address]                    List tickets owned by address (default: signer[1])
 *   transfer <ticket-id> <to-address>       Transfer ticket to another address
 *   list-resale <ticket-id> <price-eth>     List a ticket for resale
 *   cancel-listing <ticket-id>              Cancel a resale listing
 *   buy-resale <ticket-id>                  Buy a listed resale ticket
 *   create-event <name> <eth> <supply> <unix-date>  Admin: create new event
 *   withdraw                                Admin: withdraw ETH
 */
import { network } from "hardhat";
import fs from "fs";

const { ethers } = await network.connect();

function loadAddress(): string {
  try {
    return JSON.parse(fs.readFileSync("deployments/TicketOffice.json", "utf8")).address;
  } catch {
    throw new Error("Run deploy-ticket.ts first — deployments/TicketOffice.json not found");
  }
}

const artifactPath = "artifacts/contracts/TicketOffice.sol/TicketOffice.json";
const abi     = JSON.parse(fs.readFileSync(artifactPath, "utf8")).abi;
const [admin, user] = await ethers.getSigners();
const address = loadAddress();
const office  = new ethers.Contract(address, abi, admin);

const [cmd, ...args] = process.argv.slice(2);

switch (cmd) {
  case "list-events": {
    const ids: bigint[] = await office.allEventIds();
    if (ids.length === 0) { console.log("No events."); break; }
    console.log(`\nTicketOffice @ ${address}\n`);
    console.log("ID  Name                  Price (ETH)   Supply  Sold  Active  Date");
    console.log("─".repeat(70));
    for (const id of ids) {
      const [, name, price, supply, sold, date, active] = await office.getEvent(id);
      const dateStr = new Date(Number(date) * 1000).toLocaleDateString();
      console.log(
        `${String(id).padEnd(4)}${name.padEnd(22)}${ethers.formatEther(price).padEnd(14)}` +
        `${String(supply).padEnd(8)}${String(sold).padEnd(6)}${String(active).padEnd(8)}${dateStr}`
      );
    }
    break;
  }

  case "buy": {
    const [idStr] = args;
    if (!idStr) throw new Error("Usage: buy <event-id>");
    const id = BigInt(idStr);
    const [, name, price] = await office.getEvent(id);
    console.log(`Buying ticket for "${name}" @ ${ethers.formatEther(price)} ETH (as ${user.address})...`);
    const tx = await office.connect(user).buyTicket(id, { value: price });
    const rc = await tx.wait();
    // Parse TicketPurchased event to get the ticket id
    const event = rc.logs
      .map((l: any) => { try { return office.interface.parseLog(l); } catch { return null; } })
      .find((e: any) => e?.name === "TicketPurchased");
    console.log(`Ticket #${event?.args.ticketId} issued. Tx: ${rc.hash}`);
    break;
  }

  case "my-tickets": {
    const addr = args[0] ?? user.address;
    const ids: bigint[] = await office.ticketsOf(addr);
    if (ids.length === 0) { console.log(`${addr} owns no tickets.`); break; }
    console.log(`Tickets owned by ${addr}:`);
    for (const tid of ids) {
      const [, eventId] = await office.getTicket(tid);
      const [, name]    = await office.getEvent(eventId);
      const [listPrice, listed] = await office.getListing(tid);
      const listStr = listed ? ` [listed @ ${ethers.formatEther(listPrice)} ETH]` : "";
      console.log(`  Ticket #${tid} — ${name}${listStr}`);
    }
    break;
  }

  case "transfer": {
    const [tidStr, to] = args;
    if (!tidStr || !to) throw new Error("Usage: transfer <ticket-id> <to-address>");
    const tx = await office.connect(user).transferTicket(BigInt(tidStr), to);
    await tx.wait();
    console.log(`Ticket #${tidStr} transferred to ${to}`);
    break;
  }

  case "list-resale": {
    const [tidStr, ethStr] = args;
    if (!tidStr || !ethStr) throw new Error("Usage: list-resale <ticket-id> <price-eth>");
    const tx = await office.connect(user).listForResale(BigInt(tidStr), ethers.parseEther(ethStr));
    await tx.wait();
    console.log(`Ticket #${tidStr} listed for resale at ${ethStr} ETH`);
    break;
  }

  case "cancel-listing": {
    const [tidStr] = args;
    if (!tidStr) throw new Error("Usage: cancel-listing <ticket-id>");
    const tx = await office.connect(user).cancelListing(BigInt(tidStr));
    await tx.wait();
    console.log(`Listing for ticket #${tidStr} cancelled`);
    break;
  }

  case "buy-resale": {
    const [tidStr] = args;
    if (!tidStr) throw new Error("Usage: buy-resale <ticket-id>");
    const [price] = await office.getListing(BigInt(tidStr));
    const tx = await office.connect(user).buyResale(BigInt(tidStr), { value: price });
    await tx.wait();
    console.log(`Bought resale ticket #${tidStr} for ${ethers.formatEther(price)} ETH`);
    break;
  }

  case "create-event": {
    const [name, ethStr, supplyStr, dateStr] = args;
    if (!name || !ethStr || !supplyStr || !dateStr)
      throw new Error("Usage: create-event <name> <eth> <supply> <unix-date>");
    const tx = await office.createEvent(
      name, ethers.parseEther(ethStr), BigInt(supplyStr), BigInt(dateStr)
    );
    await tx.wait();
    console.log(`Created event "${name}"`);
    break;
  }

  case "withdraw": {
    const bal = await ethers.provider.getBalance(address);
    const tx  = await office.withdraw();
    await tx.wait();
    console.log(`Withdrew ${ethers.formatEther(bal)} ETH to ${admin.address}`);
    break;
  }

  default:
    console.log("Unknown command. Valid: list-events, buy, my-tickets, transfer, list-resale, cancel-listing, buy-resale, create-event, withdraw");
    process.exitCode = 1;
}
