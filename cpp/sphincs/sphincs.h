// SPHINCS+ / SLH-DSA — hash-based post-quantum signatures (FIPS PUB 205)
//
// Implements the SHAKE variant of SLH-DSA at the 128-bit security level:
//   SLH-DSA-SHAKE-128s  (n=16, h=63, d=7, k=14, a=12, w=16)
//
// All primitives are built on SHAKE256 from cpp/sha3/sha3.h — no external
// crypto library is used.  Signing is stateless and randomised.
//
// Public API:  SphincsKey  keygen(seed)
//              Signature   sign(msg, sk, randomise=true)
//              bool        verify(msg, sig, pk)
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace sphincs {

// ── Parameter set: SLH-DSA-SHAKE-128s (FIPS 205 Table 1) ────────────────────
//   n   = 16   security parameter (bytes)
//   h   = 63   total hypertree height
//   d   =  7   number of XMSS layers
//   hp  =  9   per-layer tree height (h/d)
//   a   = 12   FORS tree height (log2 of leaves per tree)
//   k   = 14   number of FORS trees
//   w   = 16   Winternitz parameter
//   m   = 30   message digest bytes
static constexpr size_t N   = 16;
static constexpr size_t H_TOTAL = 63;  // total hypertree height (FIPS 205 'h')
static constexpr size_t D   =  7;
static constexpr size_t HP  =  9;   // H / D
static constexpr size_t A   = 12;
static constexpr size_t K   = 14;
static constexpr size_t W   = 16;
static constexpr size_t M   = 30;

// Derived WOTS+ constants
static constexpr size_t LOG_W = 4;                         // log2(W)
static constexpr size_t LEN1  = (8 * N + LOG_W - 1) / LOG_W; // 32
static constexpr size_t LEN2  = 3;                         // floor(log2(LEN1*(W-1))/LOG_W)+1
static constexpr size_t LEN   = LEN1 + LEN2;              // 35

// ── Key material ─────────────────────────────────────────────────────────────

struct SecretKey {
    std::array<uint8_t, N> sk_seed;
    std::array<uint8_t, N> sk_prf;
    std::array<uint8_t, N> pk_seed;
    std::array<uint8_t, N> pk_root;
};

struct PublicKey {
    std::array<uint8_t, N> pk_seed;
    std::array<uint8_t, N> pk_root;
};

struct SphincsKey {
    SecretKey sk;
    PublicKey pk;
};

// Signature byte length:
//   R (randomiser)  : N
//   FORS sig        : K * (A+1) * N
//   HT sig          : D * (LEN + HP) * N
static constexpr size_t FORS_SIG_BYTES = K * (A + 1) * N;     // 14*(13)*16 = 2912
static constexpr size_t HT_SIG_BYTES   = D * (LEN + HP) * N;  // 7*(35+9)*16 = 4928
static constexpr size_t SIG_BYTES      = N + FORS_SIG_BYTES + HT_SIG_BYTES; // 7856

using Signature = std::vector<uint8_t>;

// ── Public API ───────────────────────────────────────────────────────────────

// Generate a key pair from a 3n-byte seed (sk_seed || sk_prf || pk_seed).
// For deterministic generation pass a fixed 48-byte value; for random keys
// fill it with a CSPRNG before calling.
SphincsKey keygen(const std::array<uint8_t, 3 * N>& seed);

// Sign msg.  If opt_rand is non-null it must point to N bytes used as the
// per-signature randomiser (set to all-zeros for deterministic signing).
// Otherwise a random N-byte value is generated via /dev/urandom.
Signature sign(const uint8_t* msg, size_t msg_len,
               const SecretKey& sk,
               const uint8_t* opt_rand = nullptr);

// Verify a signature against a message and public key.
// Returns true iff the signature is valid.
bool verify(const uint8_t* msg, size_t msg_len,
            const Signature& sig,
            const PublicKey& pk);

// Convenience overloads for std::vector messages
Signature sign(const std::vector<uint8_t>& msg, const SecretKey& sk,
               const uint8_t* opt_rand = nullptr);
bool verify(const std::vector<uint8_t>& msg, const Signature& sig,
            const PublicKey& pk);

} // namespace sphincs
