// ML-KEM — Module Lattice-Based Key Encapsulation (NIST FIPS 203)
//
// Implements ML-KEM-512 — the smallest standardised instance, targeting
// 128-bit post-quantum security.  No external crypto library; the only
// primitive is SHA-3/SHAKE from cpp/sha3/.
//
// Public API:
//   KeyPair   keygen(seed)          — deterministic from 64-byte seed
//   auto      encaps(ek, m)         — returns {SharedSecret, Ciphertext}
//   SharedSecret decaps(dk, ct)     — implicit rejection on bad ciphertext
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace mlkem {

// ── Parameter set: ML-KEM-512 (FIPS 203 Table 2) ─────────────────────────────
static constexpr int    K    = 2;     // module rank
static constexpr int    Q    = 3329;  // polynomial modulus
static constexpr int    N    = 256;   // polynomial degree
static constexpr int    ETA1 = 3;     // noise distribution for s, e  (keygen)
static constexpr int    ETA2 = 2;     // noise distribution for e1, e2 (encaps); r uses ETA1
static constexpr int    DU   = 10;    // bits per u coefficient after compression
static constexpr int    DV   = 4;     // bits per v coefficient after compression

// ── Byte-size constants ───────────────────────────────────────────────────────
static constexpr size_t EK_BYTES = 800;   // encapsulation key   (k*384 + 32)
static constexpr size_t DK_BYTES = 1632;  // decapsulation key   (768+800+32+32)
static constexpr size_t CT_BYTES = 768;   // ciphertext          (k*du*32 + dv*32)
static constexpr size_t SS_BYTES = 32;    // shared secret

using EncapKey    = std::array<uint8_t, EK_BYTES>;
using DecapKey    = std::array<uint8_t, DK_BYTES>;
using Ciphertext  = std::array<uint8_t, CT_BYTES>;
using SharedSecret = std::array<uint8_t, SS_BYTES>;

struct KeyPair { EncapKey ek; DecapKey dk; };

// Generate a key pair from a 64-byte seed (d ∥ z, each 32 bytes).
// For random keys, fill seed from a CSPRNG before calling.
// Throws std::runtime_error (astronomically unlikely; see sample_ntt).
KeyPair keygen(const std::array<uint8_t, 64>& seed);

// Encapsulate: produce a shared secret and ciphertext.
// m must be 32 uniformly random bytes (the per-encapsulation randomness).
std::pair<SharedSecret, Ciphertext>
encaps(const EncapKey& ek, const std::array<uint8_t, 32>& m);

// Decapsulate: recover the shared secret (or an implicit-rejection value).
SharedSecret decaps(const DecapKey& dk, const Ciphertext& ct);

} // namespace mlkem
