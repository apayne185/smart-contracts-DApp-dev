# Exercise 1 - Vending Machine dApp

A small decentralized application simulates a digital vending machine:
users connect a wallet, see products, buy them, and become on chain owners
of the purchased units. An admin (deployer) can add products, restock,
update prices, and withdraw collected ETH.

## Stack

- **Smart contract**: Solidity `^0.8.24`
- **Dev env**: Hardhat 3 (beta) with `hardhat-toolbox-mocha-ethers`
- **Chain**: Ganache at `127.0.0.1:8545`, chainId `1337` (docker compose provided)
- **Client**: Python 3 + `web3.py` + `eth_account` + Tkinter GUI

## Layout

```
exercise-1/
  contracts/VendingMachine.sol      # core contract
  scripts/deploy.js                 # deploy, seeds 3 products, writes ABI address - project root
  tests/VendingMachine.test.js      # Hardhat 3/Mocha test suite
  app/client.py                    # Tkinter dApp GUI (web3.py, signed txs)
  app/requirements.txt
  app/keys.example.json            # copy to keys.json w Ganache private keys
  hardhat.config.ts
  docker-compose.yml                # Ganache
  package.json
  (after deploy) deployed-address.txt
  (after deploy) VendingMachine.abi.json
```

## Running the code

```bash
cd implementation/exercise-1

npm install
(cd ../../ganache && docker compose up -d)

npx hardhat build
npx hardhat run scripts/deploy.js --network ganache

python3 -m venv .venv && source .venv/bin/activate
pip install -r app/requirements.txt
cp app/keys.example.json app/keys.json
#paste 2+ Ganache private keys frm `docker compose logs ganache` or ganache CLI outp first key should be deployer=admin

python app/client.py
```

The dropdown aloows switching between the wallets in `keys.json`. Admin buttons only get enabled when active wallet matches contract owner (
deployer) - enforced both in UI and on chain by `onlyOwner`.



## Tests

```bash
npx hardhat test
```

The testing suite covers all 5 required cases plus 1 extra:

| # | Case                                                        | Type        |
|---|-------------------------------------------------------------|-------------|
| 1 | Successful purchase emits `ProductPurchased`, updates stock | happy path  |
| 2 | Reverts on insufficient payment                             | failure     |
| 3 | Reverts on insufficient stock                               | failure     |
| 4 | Non-owner cannot restock / addProduct / updatePrice         | permission  |
| 5 | After purchase: stock -, ownership +, contract balance +    | state       |
| 6 | Overpayment is refunded to the buyer                        | extra       |

All reverts are checked w `revertedWithCustomError` so tests can verify 
specific typed error. 


## Design choices - on chain vs. off chain

**On chain:**
- Product id, name, price (wei), and stock
- Admin (owner) address
- Ownership counts per `(buyer, productId)`
- Events for every state change (`ProductAdded`, `ProductRestocked`,
  `PriceUpdated`, `ProductPurchased`, `Withdrawal`)

These are minimum trust facts users and admin must be able to verify w/out
trusting any backend: the price charged, if item is in stock, who owns
what, and who can change catalog/withdraw funds


**Off chain (out of storage on purpose):**
- Product descriptions, images, marketing copy  -not needed for trust critical
  logic, a production version would pin thse to IPFS/HTTP and store only a URI
  or  a hash on chain
- Wallet selection, session, gas estimates, tx history display - handled by 
  python client
- Catalog pagination/filtering  -not required w 3 items, client simply
  calls `allProductIds()`

**Rule of thumb:** if removing data from chain lets means a user get
cheated, it stays on chain otherwise it goes off chain. 
Prices must be on chain (the price the user sees must be the price the contract enforces), but for instance not a
product image




## Security considerations

- **Access control**: `onlyOwner` modifier with typed `NotOwner()` error on all
  admin functions (`addProduct`, `restock`,`updatePrice`,`withdraw`).
- **Input validation**: reject empty names, zero prices, zero quantities,
  unknown product ids.
- **Checks Effects Interactions**: in `purchase`, stock is decremented and
  ownership incremented before any outbound `call` (refund), preventing a
  reentrant refund recipient from observing inconsistent state.
- **Overpayment refund**: the exact excess is refunded rather than accruing to
  the contract — removes the footgun of paying slightly too much.
- **No unbounded user sriven loops**. `allProductIds()` view over a small
  catalog
- **Replay/double spend**: on chain stock decrement within a single
  transaction prevents two buyers from both claiming the last unit.
