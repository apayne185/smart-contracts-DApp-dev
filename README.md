# Blockchain & Cryptography Toolkit

[![CI](https://github.com/apayne185/smart-contracts-DApp-dev/actions/workflows/ci.yml/badge.svg)](https://github.com/apayne185/smart-contracts-DApp-dev/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

End-to-end implementations across two layers of the blockchain stack:

- **C++17 cryptographic engines** (`cpp/`) — SHA-256 from the FIPS spec, parallel proof-of-work, birthday attack cryptanalysis, and a raw Bitcoin P2PKH transaction builder. No crypto libraries.
- **Solidity smart contracts** (`contracts/`) — a vending machine and a ticketing system with secondary resale, exercised by TypeScript CLI scripts via ethers.js.

---

## Repository Layout

```
.
├── cpp/
│   ├── sha256/          SHA-256 from FIPS PUB 180-4 (no OpenSSL)
│   ├── pow/             Parallel prefix brute-forcer  (std::thread + std::atomic)
│   ├── collision/       Birthday attack on djb2 32-bit hash
│   └── bitcoin/         Raw P2PKH transaction builder (Base58Check, varint, SIGHASH_ALL)
├── contracts/
│   ├── VendingMachine.sol
│   └── TicketOffice.sol
├── scripts/
│   ├── deploy-vending.ts
│   ├── deploy-ticket.ts
│   ├── vending.ts       CLI: list, buy, add, restock, withdraw
│   └── tickets.ts       CLI: buy, transfer, resell, cancel
├── test/
│   ├── VendingMachine.test.js
│   └── TicketOffice.test.js
├── ganache/docker-compose.yml
├── CMakeLists.txt
├── hardhat.config.ts
└── package.json
```

---

## C++ Cryptographic Engines

### Build

Requires `g++ ≥ 11`, `cmake ≥ 3.16`, POSIX threads.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

Or directly with g++:

```bash
g++ -std=c++17 -O3 -march=native cpp/sha256/sha256.cpp cpp/pow/pow.cpp       -o build/pow       -lpthread
g++ -std=c++17 -O3 -march=native cpp/collision/collision.cpp                   -o build/collision -lpthread
g++ -std=c++17 -O3 -march=native cpp/sha256/sha256.cpp cpp/bitcoin/tx_builder.cpp -o build/tx_builder
```

---

### SHA-256 — `cpp/sha256/`

Verbatim implementation of FIPS PUB 180-4 §6.2 — no OpenSSL, no `<openssl/sha.h>`.

The six logical functions defined in §4.1.2:

```
Ch(x,y,z)  = (x & y) ^ (~x & z)
Maj(x,y,z) = (x & y) ^ (x & z) ^ (y & z)
Σ₀(x) = ROTR(x, 2)  ^ ROTR(x, 13) ^ ROTR(x, 22)
Σ₁(x) = ROTR(x, 6)  ^ ROTR(x, 11) ^ ROTR(x, 25)
σ₀(x) = ROTR(x, 7)  ^ ROTR(x, 18) ^ (x >> 3)
σ₁(x) = ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10)
```

Message padding, block split, message schedule (`W[0..63]`), and 64-round compression are all explicit. Used as the shared primitive by `pow` and `tx_builder`.

---

### Parallel PoW — `cpp/pow/`

Finds the smallest `N` such that `SHA256("bitcoinN")` starts with a target hex prefix — the same work function as Bitcoin block mining, at toy scale.

**Threading model:** the candidate space is striped across all hardware threads. Thread `t` owns the sub-sequence `{t, t+N_threads, t+2·N_threads, …}`. A `std::atomic<bool>` signals the field the moment any thread finds a match, causing all others to exit cleanly.

```
Thread 0: 0,  8, 16, 24, …
Thread 1: 1,  9, 17, 25, …   →  first match  →  atomic flag  →  all exit
…
Thread 7: 7, 15, 23, 31, …
```

**Benchmarks (8-core, `-O3 -march=native`):**

| Prefix | Search space | N found | Time |
|--------|-------------|---------|------|
| `cafe` | 1 in 65 536 | 42 353 | **0.047 s** |
| `faded` | 1 in 1 048 576 | 781 629 | **0.559 s** |
| `decade` | 1 in 16 777 216 | 43 531 106 | **32.1 s** |

```bash
./build/pow
```

---

### Birthday Attack — `cpp/collision/`

Finds two distinct printable-ASCII strings that produce the same 32-bit output under the `djb2` hash variant used in the original coursework:

```
h = ((h << 5) - h + c) mod 2³²   // equivalent to h * 31 + c
```

With only 2³² ≈ 4.3 billion possible digests, the birthday bound guarantees a collision after roughly √(2³²) ≈ 65 536 random inputs in expectation. An `std::unordered_map` pre-sized past the bound avoids mid-search rehashing.

| Mode | Insertions | Time |
|------|-----------|------|
| Single-threaded | 184 324 | 0.073 s |
| `--parallel` (8 threads, mutex-merged batches) | ~53 333 | 0.010 s |

```bash
./build/collision             # single-threaded, clean output + verification
./build/collision --parallel  # parallel batch-merge strategy
```

---

### Bitcoin P2PKH Transaction Builder — `cpp/bitcoin/`

Serialises a complete Pay-to-Public-Key-Hash transaction byte-for-byte without any Bitcoin library, following the Bitcoin wire protocol spec.

Implemented from scratch:

| Component | What it does |
|-----------|-------------|
| **Base58Check** | encode/decode with full checksum (hash256 of version + payload) |
| **P2PKH scriptPubKey** | `OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG` |
| **varint / CompactSize** | 1/3/5/9-byte variable-length integer encoding |
| **SIGHASH_ALL pre-image** | the exact byte sequence that gets hash256'd before signing |
| **DER signature layout** | scriptSig assembly: `<len><sig+0x01><len><compressed_pubkey>` |
| **TXID derivation** | hash256(raw_tx) reversed to display byte order |

ECDSA signing is a clearly-labelled stub — the 32-byte signing digest is computed and printed; attaching `libsecp256k1` is a one-line substitution.

```bash
./build/tx_builder
```

```
Source address (wallet A): mwAfVjnv1GGz3YXJw7z3qMZTwggx52Hbh7
Dest   address (wallet B): mzH9MtN9qHfuDjcFjiAMmNXhm5vYRP99qi
[OK] Base58Check encode/decode round-trip verified

SIGHASH_ALL preimage (114 bytes): 0100000001b2a1f6e5...
Signing digest: 3f98abeb43ab419879eb7c6c67e5b19208de8f8d89de2100fdbe3f61b1aa202b
Serialised raw transaction (191 bytes): 0100000001b2a1f6e5...
```

---

## Solidity Smart Contracts

### Prerequisites

```bash
docker compose -f ganache/docker-compose.yml up -d   # local Ganache at :8545
npm install
```

### VendingMachine — `contracts/VendingMachine.sol`

On-chain vending machine: admin manages a product catalog (name, price, stock); users purchase and receive on-chain ownership receipts; overpayment is refunded atomically.

**Design:** only trust-critical state lives on-chain (prices, stock, ownership). Product images and descriptions are off-chain by design — if removing them would let a user be deceived, they'd be on-chain. Checks-Effects-Interactions pattern prevents reentrancy on the refund path.

```bash
npm run deploy:vending

npm run vending -- list
npm run vending -- buy 1 2
npm run vending -- add "Water" 0.003 50
npm run vending -- withdraw
```

### TicketOffice — `contracts/TicketOffice.sol`

Event ticketing contract with primary sales, peer-to-peer transfers, and a secondary resale market — all enforced on-chain with no platform intermediary.

Key flows:
- **Primary:** admin creates event → user `buyTicket(eventId)` → ticket NFT minted
- **Transfer:** holder calls `transferTicket(ticketId, to)` — any active listing is cancelled atomically
- **Resale:** holder `listForResale(ticketId, price)` → buyer `buyResale(ticketId)` — ETH flows directly to seller

```bash
npm run deploy:ticket

npm run tickets -- list-events
npm run tickets -- buy 1
npm run tickets -- my-tickets
npm run tickets -- list-resale 1 0.03
npm run tickets -- buy-resale 1
npm run tickets -- transfer 1 0xRecipientAddress
```

### Tests

```bash
npm test
```

| Contract | Test cases |
|----------|-----------|
| VendingMachine | purchase success + event, insufficient payment, stock exhaustion, `onlyOwner` guard, state changes, overpayment refund |
| TicketOffice | buy + emit, insufficient payment, sold-out, transfer + emit, transfer clears listing, non-owner transfer reverts, resale full flow, self-transfer guard |
