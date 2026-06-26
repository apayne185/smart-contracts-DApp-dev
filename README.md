# Blockchain & Cryptography Toolkit

[![CI](https://github.com/apayne185/smart-contracts-DApp-dev/actions/workflows/ci.yml/badge.svg)](https://github.com/apayne185/smart-contracts-DApp-dev/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

End-to-end implementations across two layers of the blockchain stack:

- **C++17 cryptographic engines** (`cpp/`) — SHA-256, SHA-3/Keccak, and SPHINCS+ (SLH-DSA) post-quantum signatures from the FIPS specs, parallel proof-of-work, birthday attack cryptanalysis, and a raw Bitcoin P2PKH transaction builder. No crypto libraries.
- **Solidity smart contracts** (`contracts/`) — a vending machine and a ticketing system with secondary resale, exercised by TypeScript CLI scripts via ethers.js.

---

## Repository Layout

```
.
├── cpp/
│   ├── sha256/          SHA-256 from FIPS PUB 180-4 (no OpenSSL)
│   ├── sha3/            SHA-3 / Keccak from FIPS PUB 202 — SHA3-256/512, SHAKE128/256
│   ├── sphincs/         SPHINCS+ / SLH-DSA-SHAKE-128s from FIPS PUB 205 (post-quantum)
│   ├── pow/             Parallel prefix brute-forcer  (std::thread + std::atomic)
│   ├── collision/       Birthday attack on djb2 32-bit hash
│   └── bitcoin/         Raw P2PKH transaction builder (Base58Check, varint, SIGHASH_ALL)
├── contracts/
│   ├── VendingMachine.sol
│   └── TicketOffice.sol
├── scripts/
│   ├── deploy-vending.ts
│   └── deploy-ticket.ts
├── tasks/
│   ├── vending.ts       Hardhat tasks: list, buy, add, restock, price, withdraw, balance
│   └── ticket.ts        Hardhat tasks: list, buy, my-tickets, transfer, list-resale, buy-resale, create, withdraw
├── test/
│   ├── VendingMachine.test.ts
│   └── TicketOffice.test.ts
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

### SHA-3 / Keccak — `cpp/sha3/`

Verbatim implementation of FIPS PUB 202 — no OpenSSL. Provides SHA3-256, SHA3-512, SHAKE128, and SHAKE256.

The core is the **Keccak-f[1600]** permutation operating on a 5×5 array of 64-bit lanes (1600-bit state). Each of the 24 rounds applies five steps:

```
θ (Theta)  — XOR each bit with the parity of two columns
ρ (Rho)    — rotate each of the 25 lanes by a fixed offset
π (Pi)     — permute lanes to a new (x, y) position
χ (Chi)    — non-linear mixing: A[x] ^= (~A[x+1]) & A[x+2]
ι (Iota)   — XOR one of 24 round constants into A[0][0]
```

The **sponge construction** absorbs the padded message in `rate`-byte blocks, then squeezes out as many output bytes as needed — enabling both fixed-length hashes (SHA-3) and extendable output (SHAKE):

| Variant   | Rate      | Capacity  | Output  |
|-----------|-----------|-----------|---------|
| SHA3-256  | 1088 bits | 512 bits  | 256 bit |
| SHA3-512  | 576 bits  | 1024 bits | 512 bit |
| SHAKE128  | 1344 bits | 256 bits  | XOF     |
| SHAKE256  | 1088 bits | 512 bits  | XOF     |

SHA-3 is the hash function used by Ethereum (`keccak256` is the pre-standardisation variant) and is the underlying primitive for the SPHINCS+ post-quantum signature scheme below. Verified against 9 NIST FIPS 202 known-answer vectors.

```bash
./build/sha3_test
```

---

### SPHINCS+ / SLH-DSA — `cpp/sphincs/`

Post-quantum hash-based digital signatures (NIST FIPS PUB 205). Implements the **SLH-DSA-SHAKE-128s** parameter set — the smallest standardised instance, targeting 128-bit post-quantum security. No external crypto library; the only primitive is SHAKE256 from `cpp/sha3/`.

Quantum computers running Grover's algorithm halve the effective security of hash functions and break ECDSA/RSA entirely via Shor's algorithm. SPHINCS+ is immune: its security reduces only to the collision-resistance of the underlying hash, which Grover's cuts from 128 to 64 bits — still above the 64-bit threshold at this parameter set.

The scheme is a four-layer stack:

| Layer | What it does |
|-------|-------------|
| **WOTS+** | One-time signature on a single *n*-byte value: LEN=35 chains of length *w*=16 hash steps |
| **XMSS** | Merkle tree of 2^*hp*=512 WOTS+ public keys; signs one message per leaf |
| **HT** | *d*=7 stacked XMSS trees (hypertree); each layer authenticates the root below |
| **FORS** | Few-time signature on the message digest indices; *k*=14 trees of height *a*=12 |

Parameter set (FIPS 205 Table 1 — SLH-DSA-SHAKE-128s):

| Parameter | Value | Meaning |
|-----------|-------|---------|
| *n* | 16 B | security / hash output size |
| *h* | 63 | total hypertree height |
| *d* | 7 | XMSS layers |
| *h/d* | 9 | leaves per XMSS tree (512) |
| *a* | 12 | FORS tree height (4096 leaves each) |
| *k* | 14 | FORS trees |
| *w* | 16 | Winternitz parameter |
| **sig** | **7 856 B** | signature size |

The tweakable hash functions (`F`, `H`, `T_ℓ`, `PRF`, `PRF_msg`, `H_msg`) all call `SHAKE256(PK.seed ‖ ADRS ‖ input)` with a 32-byte domain-separation address (ADRS) that encodes layer, tree, and node type — preventing any cross-context hash reuse.

```bash
./build/sphincs_test
```

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

npx hardhat vending list
npx hardhat vending buy --product-id 1 --qty 2
npx hardhat vending add --name "Water" --price 0.003 --stock 50
npx hardhat vending restock --product-id 1 --qty 10
npx hardhat vending withdraw
```

### TicketOffice — `contracts/TicketOffice.sol`

Event ticketing contract with primary sales, peer-to-peer transfers, and a secondary resale market — all enforced on-chain with no platform intermediary.

Key flows:
- **Primary:** admin creates event → user `buyTicket(eventId)` → ticket NFT minted
- **Transfer:** holder calls `transferTicket(ticketId, to)` — any active listing is cancelled atomically
- **Resale:** holder `listForResale(ticketId, price)` → buyer `buyResale(ticketId)` — ETH flows directly to seller

```bash
npm run deploy:ticket

npx hardhat ticket list
npx hardhat ticket buy --event-id 1
npx hardhat ticket my-tickets
npx hardhat ticket list-resale --ticket-id 1 --price 0.03
npx hardhat ticket buy-resale --ticket-id 1
npx hardhat ticket transfer --ticket-id 1 --to 0xRecipientAddress
npx hardhat ticket withdraw
```

### Tests

```bash
npm test
```

| Contract | Test cases |
|----------|-----------|
| VendingMachine | purchase success + event, insufficient payment, stock exhaustion, `onlyOwner` guard, state changes, overpayment refund |
| TicketOffice | buy + emit, insufficient payment, sold-out, transfer + emit, transfer clears listing, non-owner transfer reverts, resale full flow, self-transfer guard |
