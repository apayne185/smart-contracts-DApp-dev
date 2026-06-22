/**
 * VendingMachine CLI
 *
 * Usage:
 *   npx hardhat run scripts/vending.ts --network ganache -- <command> [args]
 *
 * Commands:
 *   list                          List all products with id, price, stock
 *   buy   <product-id> <qty>      Purchase <qty> units of product <id>
 *   add   <name> <price-eth> <stock>  Admin: add a new product
 *   restock <product-id> <qty>    Admin: add stock to existing product
 *   price  <product-id> <eth>     Admin: update product price
 *   withdraw                      Admin: withdraw collected ETH
 *   balance <product-id> [addr]   Show owned quantity (defaults to signer[0])
 */
import { network } from "hardhat";
import fs from "fs";

const { ethers } = await network.connect();

function loadAddress(): string {
  try {
    return JSON.parse(fs.readFileSync("deployments/VendingMachine.json", "utf8")).address;
  } catch {
    throw new Error("Run deploy-vending.ts first — deployments/VendingMachine.json not found");
  }
}

const artifactPath = "artifacts/contracts/VendingMachine.sol/VendingMachine.json";
const abi = JSON.parse(fs.readFileSync(artifactPath, "utf8")).abi;
const [admin, user] = await ethers.getSigners();
const address = loadAddress();
const vm      = new ethers.Contract(address, abi, admin);

const [cmd, ...args] = process.argv.slice(2);

switch (cmd) {
  case "list": {
    const ids: bigint[] = await vm.allProductIds();
    if (ids.length === 0) { console.log("No products."); break; }
    console.log(`\nVendingMachine @ ${address}\n`);
    console.log("ID  Name              Price (ETH)   Stock");
    console.log("─".repeat(50));
    for (const id of ids) {
      const [, name, priceWei, stock] = await vm.getProduct(id);
      console.log(
        `${String(id).padEnd(4)}${name.padEnd(18)}${ethers.formatEther(priceWei).padEnd(14)}${stock}`
      );
    }
    break;
  }

  case "buy": {
    const [idStr, qtyStr] = args;
    if (!idStr || !qtyStr) throw new Error("Usage: buy <product-id> <qty>");
    const id  = BigInt(idStr);
    const qty = BigInt(qtyStr);
    const [, name, priceWei] = await vm.getProduct(id);
    const total = priceWei * qty;
    console.log(`Buying ${qty}x ${name} for ${ethers.formatEther(total)} ETH (as ${user.address})...`);
    const tx = await vm.connect(user).purchase(id, qty, { value: total });
    const rc = await tx.wait();
    console.log(`Confirmed in tx ${rc.hash}`);
    break;
  }

  case "add": {
    const [name, ethStr, stockStr] = args;
    if (!name || !ethStr || !stockStr) throw new Error("Usage: add <name> <price-eth> <stock>");
    const price = ethers.parseEther(ethStr);
    const stock = BigInt(stockStr);
    const tx = await vm.addProduct(name, price, stock);
    await tx.wait();
    console.log(`Added "${name}" @ ${ethStr} ETH (stock: ${stock})`);
    break;
  }

  case "restock": {
    const [idStr, qtyStr] = args;
    if (!idStr || !qtyStr) throw new Error("Usage: restock <product-id> <qty>");
    const tx = await vm.restock(BigInt(idStr), BigInt(qtyStr));
    await tx.wait();
    console.log(`Restocked product ${idStr} by ${qtyStr}`);
    break;
  }

  case "price": {
    const [idStr, ethStr] = args;
    if (!idStr || !ethStr) throw new Error("Usage: price <product-id> <eth>");
    const tx = await vm.updatePrice(BigInt(idStr), ethers.parseEther(ethStr));
    await tx.wait();
    console.log(`Updated product ${idStr} price to ${ethStr} ETH`);
    break;
  }

  case "withdraw": {
    const bal = await ethers.provider.getBalance(address);
    const tx  = await vm.withdraw();
    await tx.wait();
    console.log(`Withdrew ${ethers.formatEther(bal)} ETH to ${admin.address}`);
    break;
  }

  case "balance": {
    const [idStr, addr] = args;
    if (!idStr) throw new Error("Usage: balance <product-id> [address]");
    const who = addr ?? admin.address;
    const qty = await vm.balanceOf(who, BigInt(idStr));
    const [, name] = await vm.getProduct(BigInt(idStr));
    console.log(`${who} owns ${qty}x ${name}`);
    break;
  }

  default:
    console.log("Unknown command. Valid commands: list, buy, add, restock, price, withdraw, balance");
    process.exitCode = 1;
}
