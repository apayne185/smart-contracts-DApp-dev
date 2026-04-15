import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.connect();

describe("VendingMachine", function () {
  let vm, owner, alice, bob;
  const COLA  = { name: "Cola",       price: ethers.parseEther("0.01"),  stock: 5 };
  const CHIPS = { name: "Chips",      price: ethers.parseEther("0.005"), stock: 3 };
  const CHOCO = { name: "Chocolate",  price: ethers.parseEther("0.008"), stock: 2 };

  beforeEach(async () => {
    [owner, alice, bob] = await ethers.getSigners();
    vm = await ethers.deployContract("VendingMachine");
    await vm.waitForDeployment();
    await (await vm.addProduct(COLA.name,  COLA.price,  COLA.stock)).wait();   // id 1
    await (await vm.addProduct(CHIPS.name, CHIPS.price, CHIPS.stock)).wait();  // id 2
    await (await vm.addProduct(CHOCO.name, CHOCO.price, CHOCO.stock)).wait();  // id 3
  });

  // 1) successful purchase
  it("allows a user to buy a product and emits ProductPurchased", async () => {
    const qty = 2n;
    const cost = COLA.price * qty;
    await expect(vm.connect(alice).purchase(1, qty, { value: cost }))
      .to.emit(vm, "ProductPurchased")
      .withArgs(alice.address, 1n, qty, cost);

    expect(await vm.balanceOf(alice.address, 1)).to.equal(qty);
    const p = await vm.getProduct(1);
    expect(p.stock).to.equal(BigInt(COLA.stock) - qty);
  });

  // 2) failed purchase due to insufficient payment
  it("reverts on insufficient payment", async () => {
    await expect(
      vm.connect(alice).purchase(1, 1, { value: COLA.price - 1n })
    ).to.be.revertedWithCustomError(vm, "InsufficientPayment");
  });

  // 3) failed purchase due to unavailable stock
  it("reverts when buying more than available stock", async () => {
    const tooMany = BigInt(CHOCO.stock + 1);
    await expect(
      vm.connect(alice).purchase(3, tooMany, { value: CHOCO.price * tooMany })
    ).to.be.revertedWithCustomError(vm, "InsufficientStock");
  });

  // 4) permission failure: non-admin tries to restock
  it("reverts when a non-owner tries to restock", async () => {
    await expect(
      vm.connect(alice).restock(1, 5)
    ).to.be.revertedWithCustomError(vm, "NotOwner");
  });

  it("reverts when a non-owner tries to add a product or update price", async () => {
    await expect(
      vm.connect(bob).addProduct("Water", ethers.parseEther("0.001"), 1)
    ).to.be.revertedWithCustomError(vm, "NotOwner");
    await expect(
      vm.connect(bob).updatePrice(1, ethers.parseEther("0.02"))
    ).to.be.revertedWithCustomError(vm, "NotOwner");
  });

  // 5) state changes after a successful transaction
  it("updates stock, ownership, and contract balance after purchase", async () => {
    const qty = 2n;
    const cost = CHIPS.price * qty;
    const vmAddr = await vm.getAddress();
    const before = await ethers.provider.getBalance(vmAddr);

    await vm.connect(bob).purchase(2, qty, { value: cost });

    expect(await vm.balanceOf(bob.address, 2)).to.equal(qty);
    const p = await vm.getProduct(2);
    expect(p.stock).to.equal(BigInt(CHIPS.stock) - qty);

    const after = await ethers.provider.getBalance(vmAddr);
    expect(after - before).to.equal(cost);
  });

  // Extra: refund overpayment
  it("refunds overpayment to the buyer", async () => {
    const qty = 1n;
    const overpay = COLA.price + ethers.parseEther("0.05");
    const balBefore = await ethers.provider.getBalance(alice.address);

    const tx = await vm.connect(alice).purchase(1, qty, { value: overpay });
    const rcpt = await tx.wait();
    const gas = rcpt.gasUsed * rcpt.gasPrice;

    const balAfter = await ethers.provider.getBalance(alice.address);
    expect(balBefore - balAfter).to.equal(COLA.price + gas);
  });

  // Extra: restock + event
  it("admin restock increases stock and emits event", async () => {
    await expect(vm.restock(1, 7))
      .to.emit(vm, "ProductRestocked")
      .withArgs(1n, 7n, BigInt(COLA.stock + 7));
    const p = await vm.getProduct(1);
    expect(p.stock).to.equal(BigInt(COLA.stock + 7));
  });

  // Extra: withdraw
  it("only owner can withdraw collected funds", async () => {
    await vm.connect(alice).purchase(1, 1, { value: COLA.price });
    await expect(vm.connect(alice).withdraw())
      .to.be.revertedWithCustomError(vm, "NotOwner");
    await expect(vm.withdraw())
      .to.emit(vm, "Withdrawal");
  });
});
