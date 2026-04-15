import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.connect();

describe("TicketOffice", function () {
  let office, owner, alice, bob, carol;
  const ROCK = { name: "Rock Concert", price: ethers.parseEther("0.02"), supply: 3 };
  const TECH = { name: "Tech Meetup",  price: ethers.parseEther("0.01"), supply: 2 };
  const FAR_FUTURE = 4102444800; // 2100-01-01

  beforeEach(async () => {
    [owner, alice, bob, carol] = await ethers.getSigners();
    office = await ethers.deployContract("TicketOffice");
    await office.waitForDeployment();
    await (await office.createEvent(ROCK.name, ROCK.price, ROCK.supply, FAR_FUTURE)).wait(); // id 1
    await (await office.createEvent(TECH.name, TECH.price, TECH.supply, FAR_FUTURE)).wait(); // id 2
  });

  // 1) successful ticket purchase
  it("allows a user to buy a ticket and emits TicketPurchased", async () => {
    await expect(office.connect(alice).buyTicket(1, { value: ROCK.price }))
      .to.emit(office, "TicketPurchased")
      .withArgs(1n, 1n, alice.address, ROCK.price);

    const [, , , , sold] = await office.getEvent(1);
    expect(sold).to.equal(1n);
    const [, evId, ticketOwner] = await office.getTicket(1);
    expect(evId).to.equal(1n);
    expect(ticketOwner).to.equal(alice.address);
  });

  // 2) failed purchase when rules not satisfied (underpayment)
  it("reverts when payment is insufficient", async () => {
    await expect(
      office.connect(alice).buyTicket(1, { value: ROCK.price - 1n })
    ).to.be.revertedWithCustomError(office, "InsufficientPayment");
  });

  it("reverts when buying for an unknown event", async () => {
    await expect(
      office.connect(alice).buyTicket(99, { value: ROCK.price })
    ).to.be.revertedWithCustomError(office, "EventNotFound");
  });

  it("reverts when the event is sold out", async () => {
    // TECH has supply 2 — buy both then try a third.
    await office.connect(alice).buyTicket(2, { value: TECH.price });
    await office.connect(bob).buyTicket(2,   { value: TECH.price });
    await expect(
      office.connect(carol).buyTicket(2, { value: TECH.price })
    ).to.be.revertedWithCustomError(office, "SoldOut");
  });

  // 3) successful transfer
  it("owner can transfer a ticket and emits TicketTransferred", async () => {
    await office.connect(alice).buyTicket(1, { value: ROCK.price });
    await expect(office.connect(alice).transferTicket(1, bob.address))
      .to.emit(office, "TicketTransferred")
      .withArgs(1n, alice.address, bob.address);

    const [, , ticketOwner] = await office.getTicket(1);
    expect(ticketOwner).to.equal(bob.address);
  });

  // 4) failed transfer by non-owner
  it("reverts when a non-owner tries to transfer a ticket", async () => {
    await office.connect(alice).buyTicket(1, { value: ROCK.price });
    await expect(
      office.connect(bob).transferTicket(1, carol.address)
    ).to.be.revertedWithCustomError(office, "NotTicketOwner");
  });

  // 5) successful resale flow
  it("supports a full resale flow: list, buy, funds move to seller", async () => {
    await office.connect(alice).buyTicket(1, { value: ROCK.price });
    const resalePrice = ethers.parseEther("0.05");

    await expect(office.connect(alice).listForResale(1, resalePrice))
      .to.emit(office, "TicketListed")
      .withArgs(1n, alice.address, resalePrice);

    const sellerBefore = await ethers.provider.getBalance(alice.address);

    await expect(office.connect(bob).buyResale(1, { value: resalePrice }))
      .to.emit(office, "TicketResold")
      .withArgs(1n, alice.address, bob.address, resalePrice);

    const [, , ticketOwner] = await office.getTicket(1);
    expect(ticketOwner).to.equal(bob.address);

    const sellerAfter = await ethers.provider.getBalance(alice.address);
    expect(sellerAfter - sellerBefore).to.equal(resalePrice);

    const [, active] = await office.getListing(1);
    expect(active).to.equal(false);
  });

  // 6) permission failure for an admin-only action
  it("reverts when a non-admin tries to create an event or update price", async () => {
    await expect(
      office.connect(alice).createEvent("Pirate Party", ROCK.price, 5, FAR_FUTURE)
    ).to.be.revertedWithCustomError(office, "NotOwner");
    await expect(
      office.connect(alice).updatePrice(1, ethers.parseEther("1"))
    ).to.be.revertedWithCustomError(office, "NotOwner");
    await expect(
      office.connect(alice).setEventActive(1, false)
    ).to.be.revertedWithCustomError(office, "NotOwner");
  });

  // 7) edge case: repeated / invalid state transitions
  it("rejects double-listing the same ticket and cancelling an inactive listing", async () => {
    await office.connect(alice).buyTicket(1, { value: ROCK.price });
    await office.connect(alice).listForResale(1, ethers.parseEther("0.03"));
    await expect(
      office.connect(alice).listForResale(1, ethers.parseEther("0.04"))
    ).to.be.revertedWithCustomError(office, "AlreadyListed");

    await office.connect(alice).cancelListing(1);
    await expect(
      office.connect(alice).cancelListing(1)
    ).to.be.revertedWithCustomError(office, "NotListed");
  });

  it("clears the listing when the ticket is transferred, so stale buys fail", async () => {
    await office.connect(alice).buyTicket(1, { value: ROCK.price });
    await office.connect(alice).listForResale(1, ethers.parseEther("0.05"));
    await office.connect(alice).transferTicket(1, bob.address);
    // listing must be gone, stale buy fails
    await expect(
      office.connect(carol).buyResale(1, { value: ethers.parseEther("0.05") })
    ).to.be.revertedWithCustomError(office, "NotListed");
  });

  // 8) final ownership after a sequence of actions
  it("final ownership is correct after buy -> transfer -> list -> resell", async () => {
    // alice buys, gifts to bob, bob lists, carol buys
    await office.connect(alice).buyTicket(1, { value: ROCK.price });
    await office.connect(alice).transferTicket(1, bob.address);
    await office.connect(bob).listForResale(1, ethers.parseEther("0.03"));
    await office.connect(carol).buyResale(1, { value: ethers.parseEther("0.03") });

    const [, , finalOwner] = await office.getTicket(1);
    expect(finalOwner).to.equal(carol.address);

    const carolTickets = await office.ticketsOf(carol.address);
    expect(carolTickets.length).to.equal(1);
    expect(carolTickets[0]).to.equal(1n);

    const aliceTickets = await office.ticketsOf(alice.address);
    expect(aliceTickets.length).to.equal(0);
    const bobTickets = await office.ticketsOf(bob.address);
    expect(bobTickets.length).to.equal(0);
  });

  // Extras
  it("admin can pause primary sales and purchases revert while paused", async () => {
    await office.setEventActive(1, false);
    await expect(
      office.connect(alice).buyTicket(1, { value: ROCK.price })
    ).to.be.revertedWithCustomError(office, "EventInactive");
    await office.setEventActive(1, true);
    await office.connect(alice).buyTicket(1, { value: ROCK.price });
  });
});
