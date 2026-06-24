import { task } from "hardhat/config";
import { ArgumentType } from "hardhat/types/arguments";
import fs from "fs";

function loadAddress(): string {
  try {
    return JSON.parse(fs.readFileSync("deployments/VendingMachine.json", "utf8")).address;
  } catch {
    throw new Error("Run 'npx hardhat run scripts/deploy-vending.ts --network <network>' first.");
  }
}

const artifactPath = "artifacts/contracts/VendingMachine.sol/VendingMachine.json";
function loadAbi() {
  return JSON.parse(fs.readFileSync(artifactPath, "utf8")).abi;
}

// ── vending:list ──────────────────────────────────────────────────────────────
task(["vending", "list"], "List all products with id, price, and stock")
  .setInlineAction(async (_args, hre) => {
    const { ethers } = await hre.network.getOrCreate();
    const vm = new ethers.Contract(loadAddress(), loadAbi(), (await ethers.getSigners())[0]);
    const ids: bigint[] = await vm.allProductIds();
    if (ids.length === 0) { console.log("No products."); return; }
    console.log(`\nVendingMachine @ ${loadAddress()}\n`);
    console.log("ID   Name              Price (ETH)   Stock");
    console.log("─".repeat(48));
    for (const id of ids) {
      const [, name, priceWei, stock] = await vm.getProduct(id);
      console.log(`${String(id).padEnd(5)}${name.padEnd(18)}${ethers.formatEther(priceWei).padEnd(14)}${stock}`);
    }
  });

// ── vending:buy ───────────────────────────────────────────────────────────────
task(["vending", "buy"], "Purchase units of a product")
  .addOption({ name: "productId", description: "Product ID to buy", type: ArgumentType.BIGINT, defaultValue: 1n })
  .addOption({ name: "qty",       description: "Quantity to buy",   type: ArgumentType.BIGINT, defaultValue: 1n })
  .setInlineAction(async ({ productId, qty }, hre) => {
    const { ethers } = await hre.network.getOrCreate();
    const [, user] = await ethers.getSigners();
    const vm = new ethers.Contract(loadAddress(), loadAbi(), user);
    const [, name, priceWei] = await vm.getProduct(productId);
    const total = priceWei * qty;
    console.log(`Buying ${qty}x ${name} for ${ethers.formatEther(total)} ETH...`);
    const rc = await (await vm.purchase(productId, qty, { value: total })).wait();
    console.log(`Confirmed: ${rc.hash}`);
  });

// ── vending:add ───────────────────────────────────────────────────────────────
task(["vending", "add"], "Admin: add a new product")
  .addOption({ name: "name",  description: "Product name",       type: ArgumentType.STRING, defaultValue: "" })
  .addOption({ name: "price", description: "Price in ETH",       type: ArgumentType.STRING, defaultValue: "0.01" })
  .addOption({ name: "stock", description: "Initial stock",      type: ArgumentType.BIGINT, defaultValue: 10n })
  .setInlineAction(async ({ name, price, stock }, hre) => {
    const { ethers } = await hre.network.getOrCreate();
    const vm = new ethers.Contract(loadAddress(), loadAbi(), (await ethers.getSigners())[0]);
    await (await vm.addProduct(name, ethers.parseEther(price), stock)).wait();
    console.log(`Added "${name}" @ ${price} ETH (stock: ${stock})`);
  });

// ── vending:restock ───────────────────────────────────────────────────────────
task(["vending", "restock"], "Admin: add stock to an existing product")
  .addOption({ name: "productId", description: "Product ID",    type: ArgumentType.BIGINT, defaultValue: 1n })
  .addOption({ name: "qty",       description: "Units to add",  type: ArgumentType.BIGINT, defaultValue: 10n })
  .setInlineAction(async ({ productId, qty }, hre) => {
    const { ethers } = await hre.network.getOrCreate();
    const vm = new ethers.Contract(loadAddress(), loadAbi(), (await ethers.getSigners())[0]);
    await (await vm.restock(productId, qty)).wait();
    console.log(`Restocked product #${productId} by ${qty}`);
  });

// ── vending:price ─────────────────────────────────────────────────────────────
task(["vending", "price"], "Admin: update a product's price")
  .addOption({ name: "productId", description: "Product ID",    type: ArgumentType.BIGINT, defaultValue: 1n })
  .addOption({ name: "price",     description: "New price ETH", type: ArgumentType.STRING, defaultValue: "0.01" })
  .setInlineAction(async ({ productId, price }, hre) => {
    const { ethers } = await hre.network.getOrCreate();
    const vm = new ethers.Contract(loadAddress(), loadAbi(), (await ethers.getSigners())[0]);
    await (await vm.updatePrice(productId, ethers.parseEther(price))).wait();
    console.log(`Product #${productId} price updated to ${price} ETH`);
  });

// ── vending:withdraw ──────────────────────────────────────────────────────────
task(["vending", "withdraw"], "Admin: withdraw collected ETH")
  .setInlineAction(async (_args, hre) => {
    const { ethers } = await hre.network.getOrCreate();
    const admin = (await ethers.getSigners())[0];
    const vm = new ethers.Contract(loadAddress(), loadAbi(), admin);
    const bal = await ethers.provider.getBalance(loadAddress());
    await (await vm.withdraw()).wait();
    console.log(`Withdrew ${ethers.formatEther(bal)} ETH to ${admin.address}`);
  });

// ── vending:balance ───────────────────────────────────────────────────────────
task(["vending", "balance"], "Show owned quantity of a product")
  .addOption({ name: "productId", description: "Product ID",       type: ArgumentType.BIGINT, defaultValue: 1n })
  .addOption({ name: "address",   description: "Address to check", type: ArgumentType.STRING_WITHOUT_DEFAULT })
  .setInlineAction(async ({ productId, address }, hre) => {
    const { ethers } = await hre.network.getOrCreate();
    const signers = await ethers.getSigners();
    const who = address ?? signers[0].address;
    const vm = new ethers.Contract(loadAddress(), loadAbi(), signers[0]);
    const qty = await vm.balanceOf(who, productId);
    const [, name] = await vm.getProduct(productId);
    console.log(`${who} owns ${qty}x ${name}`);
  });
