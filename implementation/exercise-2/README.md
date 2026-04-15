# Exercise 2 — Ticket Office (web2 + web3)

An event-ticketing app implemented twice with the same Tkinter frontend:

- **Part A (web2)** — Flask + SQLite backend behind a REST API.
- **Part B (web3)** — `TicketOffice` Solidity contract on Ganache, called via
  `web3.py` with locally-signed transactions.

The point is to see what changes when trust moves from a centralized backend
to a smart contract. The UI code does not change.

## Layout

```
exercise-2/
  contracts/TicketOffice.sol        # web3 contract
  scripts/deploy.js                 # deploys + seeds 2 events
  tests/TicketOffice.test.js        # 10 Hardhat tests
  hardhat.config.ts
  package.json

  app/
    client.py                       # shared Tkinter UI (--mode web2|web3)
    backends/
      base.py                       # abstract interface
      web2.py                       # HTTP client to Flask
      web3_backend.py               # web3.py + contract
    server/
      app.py                        # Flask + SQLite (web2 backend)
      schema.sql
    requirements.txt
    keys.example.json               # copy to keys.json for web3 mode
```

## Running

### Common setup

```bash
cd implementation/exercise-2
npm install
python3 -m venv .venv && source .venv/bin/activate
pip install -r app/requirements.txt
```

### Part A — web2 (Flask + SQLite)

```bash
python -m app.server.app            # starts server on :5000, seeds 4 users + 2 events
# in another terminal:
python app/client.py --mode web2
```

Seeded users: `admin`, `alice`, `bob`, `carol`. Pick any from the dropdown;
only `admin` sees enabled admin buttons.

### Part B — web3 (Ganache + TicketOffice)

```bash
# 1) Ganache running at :8545 (from repo root)
(cd ../../ganache && docker compose up -d)

# 2) compile + deploy
npx hardhat build
npx hardhat run scripts/deploy.js --network ganache
#   -> deployed-address.txt, TicketOffice.abi.json

# 3) put 3+ Ganache private keys in app/keys.json (first = admin/deployer)
#    see app/keys.example.json

# 4) launch the same UI against the contract
python app/client.py --mode web3
```

`docker logs ganache-ex1` shows the deterministic accounts — account (0) is
the deployer and therefore the admin.

## Tests (web3)

```bash
npx hardhat test
```

10 tests, covering all required cases:

| # | Case                                                           |
|---|----------------------------------------------------------------|
| 1 | Successful ticket purchase (emits `TicketPurchased`, state ok) |
| 2 | Reverts on insufficient payment                                |
| 3 | Reverts when event not found                                   |
| 4 | Reverts when event is sold out                                 |
| 5 | Successful transfer by owner                                   |
| 6 | Reverts when non-owner tries to transfer                       |
| 7 | Full resale flow: list → buy → funds flow to seller            |
| 8 | Permission failures for admin-only actions                     |
| 9 | Edge cases: double-listing and cancelling an inactive listing  |
| 10| Transfer clears any stale listing                              |
| 11| Final ownership after `buy → transfer → list → resell`         |
| 12| Admin pause/resume of primary sales                            |

Each revert is checked against the specific typed custom error, not a generic
string.

## Design — what is on chain vs off chain (web3)

**On chain (in `TicketOffice.sol`):**
- `events_[id]`: name, face price, total supply, sold count, event date, active flag
- `tickets[id]`: event id, current owner
- `listings[ticketId]`: resale price (active/inactive)
- owner (admin) address
- one event per state change (`EventCreated`, `TicketPurchased`,
  `TicketTransferred`, `TicketListed`, `ListingCancelled`, `TicketResold`,
  `PriceUpdated`, `EventActiveChanged`)

These are the facts that the user needs to be able to verify or enforce
without trusting the dApp operator: the face price charged, whether a ticket
exists, who owns it, and whether a resale listing is real.

**Off chain:**
- Event descriptions, banners, venue addresses — expensive to store and not
  trust-critical. A production system would put these on IPFS and emit only
  a URI on chain.
- Wallet selection, transaction history display, formatting — the client.
- Sorting / filtering / search — done on the client.

Rule of thumb: if removing the data from chain lets a user be cheated, it
stays; otherwise it goes off chain. Ticket prices must be on chain (what the
contract charges is what the user agreed to). A flyer image does not.

## What actually changes between web2 and web3

| Concern               | web2 (Flask + SQLite)                       | web3 (TicketOffice)                      |
|-----------------------|---------------------------------------------|------------------------------------------|
| Identity              | X-User header (trivially spoofable)         | `msg.sender` from a signed transaction   |
| Authorization         | server checks `users.is_admin`              | `onlyOwner` modifier on the contract     |
| State                 | SQLite file the server can edit directly    | Public ledger, modifiable only via code  |
| Payment               | none — just an integer counter              | real ETH transferred in-transaction      |
| Resale escrow / trust | seller trusts server to pay out             | contract moves funds to seller atomically|
| Server trust required | yes: server can mint / move tickets freely  | no: admin is constrained by contract rules|
| Availability          | single server is a single point of failure  | anyone can read state from any node      |

The **frontend does not change** at all — it calls the same `Backend`
methods. Switching from `--mode web2` to `--mode web3` is the entire
"decentralization" diff from the user's point of view, which makes the trust
delta visible: in one mode the server rewrites a row; in the other the user
signs a transaction that the contract validates on chain.

## Security considerations (web3)

- **Access control** via `onlyOwner` on `createEvent`, `setEventActive`,
  `updatePrice`, `withdraw` — typed `NotOwner()` error.
- **Validation**: reject empty names, zero prices, zero supply, zero address,
  unknown ids, self-transfers, double-listings.
- **Checks-Effects-Interactions**: in `buyTicket`, `buyResale`, and the
  refund/payout paths, state is updated before any external `call`.
- **Stale listings** are cleared inside `transferTicket`, so a gift followed
  by an attempted `buyResale` reverts with `NotListed` (covered by a test).
- **Overpayment** is refunded exactly, so odd amounts don't accrue to the
  contract.
- **No unbounded loops** on trust-critical paths. `ticketsOf` is a view over
  a demo-scale catalog; a production build would index owners via events.

## How we tested

- **web3**: full Hardhat/Mocha suite in `tests/` — all required cases + a few
  edge cases (stale-listing-after-transfer, admin pause/resume).
- **web2**: manual tests from the Tkinter UI across 4 users:
  - create events as `admin`; verify non-admins see buttons disabled.
  - buy tickets until sold out; verify 400 on next attempt.
  - transfer between users, verify recipient's "My Tickets" updates.
  - list/cancel/re-list; verify "already listed" rejects the duplicate.
  - buy resale; verify seller/buyer ownership flip.
- Cross-check: the UI reports the same final state in both modes after the
  same sequence of actions, which is the end-to-end test that the backend
  abstraction is sound.
