# Exercise 2 - Ticket Office (web2 + web3)

An event ticketing app implemented twice w same Tkinter frontend:

- **Part A (web2)** -Flask +SQLite backend w REST API
- **Part B (web3)** -`TicketOffice` Solidity contract on Ganache, called 
  `web3.py` with local signed transactions

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
python -m app.server.app           
# 2nd terminal 
python app/client.py --mode web2
```

Seeded users: `admin`, `alice`, `bob`, `carol`. Pick any from the dropdown;
only `admin` sees enabled admin buttons.

### Part B — web3 (Ganache + TicketOffice)

```bash
(cd ../../ganache && docker compose up -d)

npx hardhat build
npx hardhat run scripts/deploy.js --network ganache

python app/client.py --mode web3
```

`docker logs ganache-ex1` shows deterministic accounts -account (0) is
the deployer and admin

## Tests (web3)

```bash
npx hardhat test
```

10 tests, covering all 8 cases plus 1 

| # | Case                                                           | Type     |
|---|----------------------------------------------------------------|----------|
| 1 | Successful ticket purchase (emits `TicketPurchased`, state ok) | required |
| 2 | Reverts on insufficient payment                                | required |
| 3 | Reverts when event is sold out                                 | required |
| 4 | Successful transfer by owner                                   | required |
| 5 | Reverts when non-owner tries to transfer                       | required |
| 6 | Full resale flow: list → buy → funds flow to seller            | required |
| 7 | Permission failures for admin-only actions                     | required |
| 8 | Edge cases: double-listing and cancelling an inactive listing  | required |
| 9 | Transfer clears any stale listing                              | extra    |
| 10| Final ownership after `buy → transfer → list → resell`         | required |

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

These are the facts a user needs to to verify/enforce
w/out trusting the  dApp operator



**Off chain:**
- Event descriptions, banners, venue addresses - expensive to store, not
  trust critical. A production system would put these on IPFS and emit only
  a URI on chain.
- Wallet selection, transaction history display, formatting- client.
- Sorting/filtering/search - done by client


Rule of thumb: if removing the data from chain lets a user be cheated, it
stays otherwise goes off chain. 
Ticket prices must be on chain (what
contract charges is what the user agreed to), flyer image doesnt

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

The **frontend does not change** at all, it calls the same `Backend`
methods. Switching from `--mode web2` to `--mode web3` is the entire
decentralization diff from the user pov, which makes the trust
delta visible. in one mode the server rewrites a row in the other the user
signs a transaction that the contract validates on chain

## Security considerations (web3)

- **Access control** via `onlyOwner` on `createEvent`, `setEventActive`,
  `updatePrice`, `withdraw` - typed `NotOwner()` error.
- **Validation**: reject empty names, zero prices, zero supply, zero address,
  unknown ids, self-transfers, double listings.
- **Checks-Effects-Interactions**: in `buyTicket`, `buyResale`, and the
  refund/payout paths, state is updated before any external `call`.
- **Stale listings** are cleared inside `transferTicket`, so a gift followed
  by an attempted `buyResale` reverts with `NotListed` (covered by a test).
- **Overpayment** is refunded exactly, so odd amounts dont acrue to the
  contract.
- **No unbounded loops** on trust critical paths. `ticketsOf` is a view over
  a democale catalog, a production build would idnex owners by events




## How i tested

- **web3**: full Hardhat/Mocha suite in `tests/` - all required cases and few
  edge cases (stale listing after transfer, admin pause/resume).
- **web2**: manual tests from the Tkinter UI across 4 users:
  - create events as `admin`; verify nonadmins see buttons disabled.
  - buy tickets until sold out verify 400 on next attempt
  - transfer between users - see if recipient's "My Tickets" updates
  - list/cancel/relist - verify if "already listed" rejects duplicates
  - buy resale verify seller/buyer ownership flip.
- Cross check: the UI reports the same final state in both modes after the
  same sequence of actions,  end to end test to see if  backend
  abstraction is done
