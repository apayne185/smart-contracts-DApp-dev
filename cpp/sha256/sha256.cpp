// SHA-256 implemented from FIPS PUB 180-4
// https://csrc.nist.gov/publications/detail/fips/180/4/final
#include "sha256.h"
#include <cstring>
#include <sstream>
#include <iomanip>

namespace sha256 {

// ── Constants ────────────────────────────────────────────────────────────────

// First 32 bits of the fractional parts of the cube roots of the first 64 primes
static constexpr std::array<uint32_t, 64> K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

// First 32 bits of the fractional parts of the square roots of the first 8 primes
static constexpr std::array<uint32_t, 8> H0 = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

// ── Bit operations ───────────────────────────────────────────────────────────

static inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

// Section 4.1.2 — SHA-256 functions
static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)  { return (x & y) ^ (~x & z); }
static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static inline uint32_t Sigma0(uint32_t x) { return rotr(x, 2)  ^ rotr(x, 13) ^ rotr(x, 22); }
static inline uint32_t Sigma1(uint32_t x) { return rotr(x, 6)  ^ rotr(x, 11) ^ rotr(x, 25); }
static inline uint32_t sigma0(uint32_t x) { return rotr(x, 7)  ^ rotr(x, 18) ^ (x >> 3);   }
static inline uint32_t sigma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);  }

// ── Core block compression ───────────────────────────────────────────────────

// Processes one 512-bit (64-byte) block, updating the 8-word state in place.
static void compress(std::array<uint32_t, 8>& state, const uint8_t block[64]) {
    // Message schedule (Section 6.2.2, Step 1)
    uint32_t W[64];
    for (int t = 0; t < 16; ++t) {
        W[t] = (uint32_t(block[t * 4])     << 24)
             | (uint32_t(block[t * 4 + 1]) << 16)
             | (uint32_t(block[t * 4 + 2]) <<  8)
             |  uint32_t(block[t * 4 + 3]);
    }
    for (int t = 16; t < 64; ++t) {
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
    }

    // Working variables (Section 6.2.2, Step 2)
    auto [a, b, c, d, e, f, g, h] = state;

    // 64 rounds (Section 6.2.2, Step 3)
    for (int t = 0; t < 64; ++t) {
        uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
        uint32_t T2 = Sigma0(a) + Maj(a, b, c);
        h = g; g = f; f = e;
        e = d + T1;
        d = c; c = b; b = a;
        a = T1 + T2;
    }

    // Add compressed chunk to current hash (Section 6.2.2, Step 4)
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// ── Public API ───────────────────────────────────────────────────────────────

Digest hash(const uint8_t* data, size_t len) {
    // Section 5.1.1 — Padding
    // Message length in bits must be appended as a 64-bit big-endian integer
    // after a '1' bit and enough '0' bits to reach 448 mod 512 bits.
    uint64_t bit_len = uint64_t(len) * 8;
    size_t padded_len = len + 1; // +1 for the 0x80 byte
    while (padded_len % 64 != 56) padded_len++;
    padded_len += 8; // +8 for the 64-bit length field

    std::vector<uint8_t> msg(padded_len, 0);
    std::memcpy(msg.data(), data, len);
    msg[len] = 0x80; // Append bit '1' followed by zeros
    // Append original length as big-endian 64-bit integer (Section 5.1.1)
    for (int i = 0; i < 8; ++i)
        msg[padded_len - 8 + i] = uint8_t(bit_len >> (56 - i * 8));

    // Section 6.2 — Hash computation
    auto state = std::array<uint32_t, 8>(H0);
    for (size_t i = 0; i < padded_len; i += 64)
        compress(state, msg.data() + i);

    // Section 6.2.2 — Produce final digest (big-endian word encoding)
    Digest digest;
    for (int i = 0; i < 8; ++i) {
        digest[i * 4]     = uint8_t(state[i] >> 24);
        digest[i * 4 + 1] = uint8_t(state[i] >> 16);
        digest[i * 4 + 2] = uint8_t(state[i] >>  8);
        digest[i * 4 + 3] = uint8_t(state[i]);
    }
    return digest;
}

Digest hash(const std::string& s) {
    return hash(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

std::string to_hex(const Digest& d) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : d) ss << std::setw(2) << int(byte);
    return ss.str();
}

} // namespace sha256
