# Post-Quantum Cryptography & Blockchain Toolkit

[![CI](https://github.com/apayne185/smart-contracts-DApp-dev/actions/workflows/ci.yml/badge.svg)](https://github.com/apayne185/smart-contracts-DApp-dev/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

From-specification implementations of the NIST post-quantum standards and the hash primitives beneath them, written in dependency-free C++17, alongside Solidity contracts and TypeScript tooling for the application layer.

- **Post-quantum cryptography** (`cpp/`): ML-KEM-512 key encapsulation (FIPS 203) and SLH-DSA-SHAKE-128s signatures (FIPS 205), built on a from-scratch SHA-3/Keccak (FIPS 202). Verified against NIST known-answer vectors, tested under AddressSanitizer and UndefinedBehaviorSanitizer, and built with gcc and clang on Linux and macOS in CI.
- **Blockchain primitives** (`cpp/`): SHA-256 (FIPS 180-4), a multithreaded proof-of-work search, and a byte-exact Bitcoin P2PKH transaction serialiser.
- **Smart contracts** (`contracts/`): an event ticketing system with a peer-to-peer resale market and an on-chain vending machine, tested with Hardhat 3 and driven by typed CLI tasks.

> **Security notice.** This code has not been audited. It is written to be correct and side-channel aware, but it is a learning and portfolio project. Do not use it to protect real assets or data. See [Security model](#security-model).

---

## Contents

- [Repository layout](#repository-layout)
- [Quick start](#quick-start)
- [Post-quantum engines](#post-quantum-engines)
- [Hash functions](#hash-functions)
- [Blockchain primitives](#blockchain-primitives)
- [Smart contracts](#smart-contracts)
- [Security model](#security-model)
- [Engineering practices](#engineering-practices)
- [Roadmap](#roadmap)

---

## Repository layout

```
.
├── cpp/
│   ├── mlkem/        ML-KEM-512 key encapsulation (FIPS 203)
│   ├── sphincs/      SLH-DSA-SHAKE-128s signatures (FIPS 205)
│   ├── sha3/         SHA-3 / Keccak, SHA3-256/512, SHAKE128/256 (FIPS 202)
│   ├── sha256/       SHA-256 (FIPS 180-4)
│   ├── common/       randombytes: OS CSPRNG wrapper (getrandom / getentropy)
│   ├── pow/          Multithreaded SHA-256 prefix search
│   ├── collision/    Birthday attack on a 32-bit hash
│   └── bitcoin/      Raw P2PKH transaction builder
├── contracts/        TicketOffice.sol, VendingMachine.sol
├── tasks/            Hardhat CLI tasks for interacting with deployed contracts
├── scripts/          Deployment scripts
├── test/             Hardhat + Mocha + Chai contract tests
└── .github/          CI workflow and Dependabot configuration
```

---

## Quick start

### C++ engines

Requires a C++17 compiler (gcc 11+ or clang 14+) and CMake 3.16+.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Build options:

| Option | Default | Effect |
|--------|---------|--------|
| `CRYPTO_NATIVE_ARCH` | `OFF` | Tune for the host CPU with `-march=native`. Faster, but the binaries are not portable. |
| `CRYPTO_WERROR` | `OFF` | Treat warnings as errors. Enabled in CI. |
| `CRYPTO_SANITIZE` | `OFF` | Build with AddressSanitizer and UndefinedBehaviorSanitizer. |

### Smart contracts

Requires Node.js 22+.

```bash
npm ci
npm run build        # compile contracts and generate TypeChain typings
npm run typecheck    # strict tsc over config, tasks, scripts, and tests
npm test             # Hardhat test suite
```

---

## Post-quantum engines

Shor's algorithm breaks RSA and elliptic-curve cryptography, including the ECDSA signatures that secure Bitcoin and Ethereum today. NIST standardised replacements in 2024. This repository implements the two that cover the core needs of a blockchain client: key exchange and signatures.

### ML-KEM-512 (`cpp/mlkem/`)

Module-lattice key encapsulation, NIST FIPS 203 (formerly CRYSTALS-Kyber). Two parties use it to agree a 32-byte shared secret over an untrusted channel. Its security rests on the Module Learning With Errors problem, for which no efficient quantum algorithm is known.

```cpp
#include "mlkem/mlkem.h"
#include "common/randombytes.h"

std::array<uint8_t, 64> seed;  crypto::randombytes(seed.data(), seed.size());
std::array<uint8_t, 32> m;     crypto::randombytes(m.data(), m.size());

auto kp       = mlkem::keygen(seed);            // (ek, dk)
auto [ss, ct] = mlkem::encaps(kp.ek, m);        // sender
auto ss2      = mlkem::decaps(kp.dk, ct);       // receiver: ss2 == ss
```

| Parameter | Value | Meaning |
|-----------|-------|---------|
| *k* | 2 | module rank |
| *q* | 3329 | coefficient modulus |
| *n* | 256 | polynomial degree |
| *η₁*, *η₂* | 3, 2 | centred binomial noise widths |
| *d_u*, *d_v* | 10, 4 | ciphertext compression bits |
| sizes | ek 800 B, dk 1632 B, ct 768 B | |

Implementation notes:

- Number-theoretic transform (NTT) for polynomial multiplication, with matrix **Â** expanded from SHAKE128 by rejection sampling (`sample_ntt`) using the FIPS 203 index order.
- The Fujisaki-Okamoto transform with **implicit rejection**: decapsulation re-encrypts and, if the ciphertext was tampered with, returns a pseudorandom value derived from the secret *z* rather than an error. The comparison and selection are branch-free.
- Modular reduction uses arithmetic masking instead of conditional branches to avoid secret-dependent timing.
- Secret intermediates (PRF output, *ρ‖σ*, *m′*) are wiped with a volatile write loop the compiler cannot elide.
- Tested against the NIST ACVP known-answer vectors for keygen, encaps, and decaps, plus tamper, wrong-key, and determinism checks.

### SLH-DSA-SHAKE-128s (`cpp/sphincs/`)

Stateless hash-based signatures, NIST FIPS 205 (formerly SPHINCS+). Security reduces only to properties of the underlying hash function, which makes it the most conservative of the post-quantum signature standards. The 128s parameter set targets NIST security category 1 and optimises for small signatures.

The scheme is a four-layer stack:

| Layer | Role |
|-------|------|
| **WOTS+** | One-time signature on an *n*-byte value: 35 hash chains of length 16 |
| **XMSS** | Merkle tree of 2⁹ = 512 WOTS+ keys |
| **Hypertree** | 7 stacked XMSS layers, each authenticating the root below it |
| **FORS** | Few-time signature on the message digest: 14 trees of height 12 |

| Parameter | Value |
|-----------|-------|
| *n* | 16 B |
| *h*, *d* | 63, 7 |
| *a*, *k* | 12, 14 |
| *w* | 16 |
| signature | 7 856 B |

Every tweakable hash (`F`, `H`, `T_ℓ`, `PRF`, `PRF_msg`, `H_msg`) is `SHAKE256(PK.seed ‖ ADRS ‖ input)`, where the 32-byte address encodes layer, tree, and node type so that no hash call can be replayed in another context. Changing the address type clears its trailing fields, as FIPS 205 §4.3 requires.

`sign` and `verify` implement the FIPS 205 **pure** interface (Algorithms 22 and 24). An optional context string of up to 255 bytes binds a signature to its purpose, so a signature made for one application cannot be replayed in another. Signing is randomised by default using `crypto::randombytes`; passing `PK.seed` as `opt_rand` selects the deterministic variant.

```cpp
std::vector<uint8_t> ctx = {'t', 'x', '-', 'v', '1'};
auto kp  = sphincs::keygen(seed48);
auto sig = sphincs::sign(msg, kp.sk, ctx);       // randomised
bool ok  = sphincs::verify(msg, sig, kp.pk, ctx);
```

Validated against the NIST ACVP vectors for key generation, the internal signing interface, and the pure interface (including empty and maximum-length contexts). Checking against these vectors found and fixed two deviations from FIPS 205 in XMSS hashing that round-trip tests could not detect, because signing and verification shared them.

---

## Hash functions

### SHA-3 / Keccak (`cpp/sha3/`)

FIPS 202: SHA3-256, SHA3-512, SHAKE128, and SHAKE256 over the Keccak-f[1600] permutation. Each of the 24 rounds applies θ (column parity), ρ (lane rotation), π (lane permutation), χ (the only non-linear step), and ι (round constant). The sponge absorbs input at the rate and squeezes arbitrary-length output, which is what lets SHAKE act as the XOF and PRF inside both post-quantum schemes.

| Variant | Rate | Capacity | Output |
|---------|------|----------|--------|
| SHA3-256 | 1088 bits | 512 bits | 256 bits |
| SHA3-512 | 576 bits | 1024 bits | 512 bits |
| SHAKE128 | 1344 bits | 256 bits | variable |
| SHAKE256 | 1088 bits | 512 bits | variable |

Verified against NIST FIPS 202 known-answer vectors.

### SHA-256 (`cpp/sha256/`)

FIPS 180-4 §6.2 with explicit padding, message schedule, and 64-round compression. Used by the proof-of-work search and the Bitcoin transaction builder. Verified against NIST FIPS 180-4 vectors.

---

## Blockchain primitives

### Parallel proof-of-work (`cpp/pow/`)

Finds the smallest `N` such that `SHA256("bitcoinN")` begins with a target hex prefix, the same shape of work as Bitcoin mining at toy difficulty. The search space is striped across hardware threads (thread *t* tries *t*, *t + T*, *t + 2T*, ...) and a `std::atomic<bool>` stops every worker as soon as one finds a match.

| Prefix | Expected tries | N found | Time (8 cores, native build) |
|--------|----------------|---------|------------------------------|
| `cafe` | 2¹⁶ | 42 353 | 0.047 s |
| `faded` | 2²⁰ | 781 629 | 0.559 s |
| `decade` | 2²⁴ | 43 531 106 | 32.1 s |

```bash
./build/pow cafe
```

### Birthday attack (`cpp/collision/`)

Finds two printable strings with the same 32-bit djb2-style hash (`h = h * 31 + c mod 2³²`). With 2³² possible outputs, a collision is expected after about 2¹⁶ inputs. Includes a multithreaded variant that merges per-thread batches.

### Bitcoin P2PKH transaction builder (`cpp/bitcoin/`)

Serialises a Pay-to-Public-Key-Hash transaction byte for byte with no Bitcoin library: Base58Check encode and decode, the `OP_DUP OP_HASH160 ... OP_CHECKSIG` script, CompactSize varints, the SIGHASH_ALL preimage, scriptSig layout, and TXID derivation. ECDSA signing is a labelled stub that prints the 32-byte digest to be signed.

---

## Smart contracts

### TicketOffice (`contracts/TicketOffice.sol`)

Event ticketing with primary sales, gifting, and a secondary resale market enforced on-chain without a platform intermediary. Tickets are tracked as contract records (not ERC-721 tokens; see the [roadmap](#roadmap)).

- **Primary sale:** the organiser creates an event; `buyTicket(eventId)` issues a ticket and refunds any overpayment.
- **Transfer:** `transferTicket(ticketId, to)` moves a ticket and atomically cancels any active resale listing, so a gifted ticket cannot still be bought.
- **Resale:** `listForResale` then `buyResale` moves ownership and pays the seller directly. State is updated before any external call (checks-effects-interactions).

### VendingMachine (`contracts/VendingMachine.sol`)

An owner-managed catalogue with on-chain stock and per-buyer ownership records. Only trust-critical data (price, stock, ownership) lives on-chain; descriptions and images belong off-chain.

### Running locally

```bash
npm run node              # terminal 1: local Hardhat node on :8545
npm run deploy:vending    # terminal 2
npm run deploy:ticket
```

```bash
npx hardhat vending list --network localhost
npx hardhat vending buy --product-id 1 --qty 2 --network localhost
npx hardhat vending balance --product-id 1 --network localhost

npx hardhat ticket list --network localhost
npx hardhat ticket buy --event-id 1 --network localhost
npx hardhat ticket list-resale --ticket-id 1 --price 0.03 --network localhost
npx hardhat ticket buy-resale --ticket-id 1 --network localhost
```

Run `npx hardhat vending` or `npx hardhat ticket` to list every subcommand. To deploy to Sepolia, copy `.env.example` to `.env` and fill in the RPC URL and deployer key.

---

## Security model

**In scope.** Functional correctness against the NIST specifications, verified with NIST ACVP known-answer tests for ML-KEM, SLH-DSA, SHA-3, and SHA-256. Memory safety, checked by running the full test suite under ASan and UBSan in CI. Basic timing hygiene in ML-KEM: branch-free reduction and decapsulation selection, plus wiping of secret intermediates.

**Not yet verified.**

- Constant-time behaviour is enforced in the source but has not been checked at the binary level (for example with dudect or a Valgrind-based taint check). Compilers can reintroduce branches.
- The FIPS 205 pre-hash signing variant (HashSLH-DSA) is not implemented.
- Power, electromagnetic, and fault-injection attacks are out of scope.
- The smart contracts have not been audited or formally verified.

Randomness comes only from the operating system (`getrandom` on Linux, `getentropy` on macOS and BSD); there is no fallback to a non-cryptographic generator. To report a problem, see [SECURITY.md](SECURITY.md).

---

## Engineering practices

- **CI** on every pull request: gcc and clang on Ubuntu, clang on macOS, all with `-Werror`; a separate ASan + UBSan job; contract compilation, strict TypeScript type checking, and tests.
- **Supply chain:** third-party GitHub Actions are pinned to commit SHAs, the workflow token is read-only, and Dependabot keeps actions and npm packages current.
- **Portable builds:** no host-specific flags by default; per-target warnings via a CMake interface library.
- **No crypto dependencies:** every primitive is implemented from its FIPS document, with section references in the source.

---

## Roadmap

- [x] FIPS 205 known-answer vectors and the pure signing interface for SLH-DSA
- [ ] libFuzzer harnesses for decapsulation, signature verification, and Base58 decoding
- [ ] Binary-level constant-time verification in CI
- [ ] Benchmarks (cycles per operation) compared against liboqs
- [ ] Migrate TicketOffice to ERC-721 with OpenZeppelin `Ownable2Step`, `Pausable`, and `ReentrancyGuard`
- [ ] Enforce event dates and add an optional resale price cap
- [ ] Foundry fuzz and invariant tests, Slither static analysis, and coverage gating
- [ ] Verified Sepolia deployment and a web front end

---

## License

[MIT](LICENSE)
