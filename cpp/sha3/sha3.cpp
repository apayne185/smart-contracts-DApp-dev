// SHA-3 / Keccak implementation — FIPS PUB 202
//
// Implements the Keccak-f[1600] permutation and the sponge construction for:
//   SHA3-256, SHA3-512  (fixed-length output, domain suffix 0x06)
//   SHAKE128, SHAKE256  (extendable output,   domain suffix 0x1F)
//
// The 1600-bit state is a 5×5 array of 64-bit lanes stored in little-endian
// byte order. On little-endian hosts (x86/ARM-LE) the byte-level XOR into
// the state array is a direct reinterpretation; no byteswap is needed.
//
// Reference: NIST FIPS PUB 202, August 2015.
#include "sha3.h"
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace sha3 {

// ── Keccak-f[1600] permutation ───────────────────────────────────────────────

// 24 round constants derived from the LFSR in Keccak spec §1.2
static constexpr std::array<uint64_t, 24> RC = {{
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
    0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
}};

// ρ rotation offsets: RHO[x + 5*y] is the rotation amount for lane A[x][y]
static constexpr std::array<int, 25> RHO = {{
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
}};

static constexpr uint64_t rotl64(uint64_t x, int n) noexcept {
    return n == 0 ? x : (x << n) | (x >> (64 - n));
}

static void keccak_f1600(uint64_t A[25]) noexcept {
    for (int rnd = 0; rnd < 24; ++rnd) {
        // θ: XOR each column parity into neighbouring columns
        uint64_t C[5], D[5];
        for (int x = 0; x < 5; ++x)
            C[x] = A[x] ^ A[x+5] ^ A[x+10] ^ A[x+15] ^ A[x+20];
        for (int x = 0; x < 5; ++x)
            D[x] = C[(x+4)%5] ^ rotl64(C[(x+1)%5], 1);
        for (int i = 0; i < 25; ++i)
            A[i] ^= D[i % 5];

        // ρ + π: rotate each lane, then scatter to new (x,y) position
        // π: A'[y][2x+3y mod 5] = ρ(A[x][y])
        uint64_t B[25];
        for (int y = 0; y < 5; ++y)
            for (int x = 0; x < 5; ++x)
                B[y + 5*((2*x + 3*y) % 5)] = rotl64(A[x + 5*y], RHO[x + 5*y]);

        // χ: non-linear mixing within each row
        for (int y = 0; y < 5; ++y)
            for (int x = 0; x < 5; ++x)
                A[x + 5*y] = B[x + 5*y] ^ ((~B[(x+1)%5 + 5*y]) & B[(x+2)%5 + 5*y]);

        // ι: XOR round constant into A[0][0]
        A[0] ^= RC[rnd];
    }
}

// ── Sponge construction ──────────────────────────────────────────────────────

// Domain separation bytes (FIPS 202 §6.1 / §6.2)
static constexpr uint8_t DOMAIN_SHA3  = 0x06; // "01" suffix + pad10*1
static constexpr uint8_t DOMAIN_SHAKE = 0x1F; // "1111" suffix + pad10*1

// XOR one byte into the state, treating the uint64_t lanes as LE byte arrays.
static inline void xor_byte(uint64_t state[25], size_t pos, uint8_t byte) noexcept {
    state[pos / 8] ^= static_cast<uint64_t>(byte) << (8 * (pos % 8));
}

// Read one byte out of the state in the same LE lane layout.
static inline uint8_t read_byte(const uint64_t state[25], size_t pos) noexcept {
    return static_cast<uint8_t>(state[pos / 8] >> (8 * (pos % 8)));
}

struct Sponge {
    uint64_t state[25] = {};
    size_t   rate;      // absorb/squeeze block size in bytes
    size_t   pos = 0;   // byte cursor within the current block

    explicit Sponge(size_t rate_bytes) : rate(rate_bytes) {
        memset(state, 0, sizeof(state));
    }

    void absorb(const uint8_t* data, size_t len) noexcept {
        for (size_t i = 0; i < len; ++i) {
            xor_byte(state, pos++, data[i]);
            if (pos == rate) { keccak_f1600(state); pos = 0; }
        }
    }

    void finalize(uint8_t domain) noexcept {
        // pad10*1: domain separator at current position, 0x80 at end of block
        xor_byte(state, pos, domain);
        xor_byte(state, rate - 1, 0x80);
        keccak_f1600(state);
        pos = 0;
    }

    std::vector<uint8_t> squeeze(size_t outbytes) noexcept {
        std::vector<uint8_t> out(outbytes);
        for (size_t i = 0; i < outbytes; ++i) {
            if (pos == rate) { keccak_f1600(state); pos = 0; }
            out[i] = read_byte(state, pos++);
        }
        return out;
    }
};

// ── Internal helper ──────────────────────────────────────────────────────────

static std::vector<uint8_t> sponge_hash(
    const uint8_t* data, size_t len,
    size_t rate, size_t outbytes, uint8_t domain)
{
    Sponge s(rate);
    s.absorb(data, len);
    s.finalize(domain);
    return s.squeeze(outbytes);
}

// ── Public API ───────────────────────────────────────────────────────────────

Digest256 sha3_256(const uint8_t* data, size_t len) {
    auto v = sponge_hash(data, len, 136, 32, DOMAIN_SHA3);
    Digest256 d; std::copy(v.begin(), v.end(), d.begin()); return d;
}
Digest256 sha3_256(std::string_view s) {
    return sha3_256(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

Digest512 sha3_512(const uint8_t* data, size_t len) {
    auto v = sponge_hash(data, len, 72, 64, DOMAIN_SHA3);
    Digest512 d; std::copy(v.begin(), v.end(), d.begin()); return d;
}
Digest512 sha3_512(std::string_view s) {
    return sha3_512(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

std::vector<uint8_t> shake128(const uint8_t* data, size_t len, size_t outbytes) {
    return sponge_hash(data, len, 168, outbytes, DOMAIN_SHAKE);
}
std::vector<uint8_t> shake128(std::string_view s, size_t outbytes) {
    return shake128(reinterpret_cast<const uint8_t*>(s.data()), s.size(), outbytes);
}

std::vector<uint8_t> shake256(const uint8_t* data, size_t len, size_t outbytes) {
    return sponge_hash(data, len, 136, outbytes, DOMAIN_SHAKE);
}
std::vector<uint8_t> shake256(std::string_view s, size_t outbytes) {
    return shake256(reinterpret_cast<const uint8_t*>(s.data()), s.size(), outbytes);
}

// ── Hex utility ──────────────────────────────────────────────────────────────

std::string to_hex(const uint8_t* data, size_t len) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) ss << std::setw(2) << int(data[i]);
    return ss.str();
}

std::string to_hex(const std::vector<uint8_t>& d) { return to_hex(d.data(), d.size()); }

template <size_t N>
std::string to_hex(const std::array<uint8_t, N>& d) { return to_hex(d.data(), N); }

// Explicit instantiations
template std::string to_hex(const std::array<uint8_t, 32>&);
template std::string to_hex(const std::array<uint8_t, 64>&);

} // namespace sha3
