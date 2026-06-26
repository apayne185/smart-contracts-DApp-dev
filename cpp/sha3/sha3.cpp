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

// The fast-absorb path word-XORs 8 bytes at a time, which is correct only on
// little-endian hosts where a uint64_t lane and its byte representation agree.
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
              "sha3: fast absorb path requires little-endian host");
#endif

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


static constexpr uint64_t rotl64(uint64_t x, int n) noexcept {
    return n == 0 ? x : (x << n) | (x >> (64 - n));
}

// Optimised Keccak-f[1600] permutation.
// All modulo-5 operations are eliminated by expanding θ, ρ+π, and χ into
// explicit scalar assignments.  This avoids integer division and removes the
// modulo-dependent loop-carried dependency chains that prevent auto-vectorisation.
static void keccak_f1600(uint64_t A[25]) noexcept {
    for (int rnd = 0; rnd < 24; ++rnd) {
        // θ: column parities (explicit)
        uint64_t C0 = A[0]^A[5]^A[10]^A[15]^A[20];
        uint64_t C1 = A[1]^A[6]^A[11]^A[16]^A[21];
        uint64_t C2 = A[2]^A[7]^A[12]^A[17]^A[22];
        uint64_t C3 = A[3]^A[8]^A[13]^A[18]^A[23];
        uint64_t C4 = A[4]^A[9]^A[14]^A[19]^A[24];
        uint64_t D0 = C4 ^ rotl64(C1,1);
        uint64_t D1 = C0 ^ rotl64(C2,1);
        uint64_t D2 = C1 ^ rotl64(C3,1);
        uint64_t D3 = C2 ^ rotl64(C4,1);
        uint64_t D4 = C3 ^ rotl64(C0,1);
        A[ 0]^=D0; A[ 1]^=D1; A[ 2]^=D2; A[ 3]^=D3; A[ 4]^=D4;
        A[ 5]^=D0; A[ 6]^=D1; A[ 7]^=D2; A[ 8]^=D3; A[ 9]^=D4;
        A[10]^=D0; A[11]^=D1; A[12]^=D2; A[13]^=D3; A[14]^=D4;
        A[15]^=D0; A[16]^=D1; A[17]^=D2; A[18]^=D3; A[19]^=D4;
        A[20]^=D0; A[21]^=D1; A[22]^=D2; A[23]^=D3; A[24]^=D4;

        // ρ + π: combined into B[] using the fixed permutation derived from
        // B[y + 5*((2x+3y)%5)] = rotl64(A[x+5y], RHO[x+5y])
        uint64_t B[25];
        B[ 0]=rotl64(A[ 0], 0); B[10]=rotl64(A[ 1], 1); B[20]=rotl64(A[ 2],62);
        B[ 5]=rotl64(A[ 3],28); B[15]=rotl64(A[ 4],27); B[16]=rotl64(A[ 5],36);
        B[ 1]=rotl64(A[ 6],44); B[11]=rotl64(A[ 7], 6); B[21]=rotl64(A[ 8],55);
        B[ 6]=rotl64(A[ 9],20); B[ 7]=rotl64(A[10], 3); B[17]=rotl64(A[11],10);
        B[ 2]=rotl64(A[12],43); B[12]=rotl64(A[13],25); B[22]=rotl64(A[14],39);
        B[23]=rotl64(A[15],41); B[ 8]=rotl64(A[16],45); B[18]=rotl64(A[17],15);
        B[ 3]=rotl64(A[18],21); B[13]=rotl64(A[19], 8); B[14]=rotl64(A[20],18);
        B[24]=rotl64(A[21], 2); B[ 9]=rotl64(A[22],61); B[19]=rotl64(A[23],56);
        B[ 4]=rotl64(A[24],14);

        // χ: non-linear mixing, row by row (no % — reads b0..b4 explicitly)
        for (int y = 0; y < 5; ++y) {
            uint64_t b0=B[5*y],b1=B[5*y+1],b2=B[5*y+2],b3=B[5*y+3],b4=B[5*y+4];
            A[5*y+0] = b0^((~b1)&b2);
            A[5*y+1] = b1^((~b2)&b3);
            A[5*y+2] = b2^((~b3)&b4);
            A[5*y+3] = b3^((~b4)&b0);
            A[5*y+4] = b4^((~b0)&b1);
        }

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
        size_t i = 0;
        // Fast path: XOR 8 bytes at a time when at a word boundary.
        // The state lanes are stored in little-endian byte order, so on LE hosts
        // (x86/ARM-LE) a word-level memcpy+XOR is equivalent to byte-by-byte.
        while (i < len) {
            if ((pos & 7) == 0 && i + 8 <= len && pos + 8 <= rate) {
                uint64_t w;
                memcpy(&w, data + i, 8);
                state[pos >> 3] ^= w;
                pos += 8;
                i   += 8;
            } else {
                xor_byte(state, pos++, data[i++]);
            }
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

void shake256_into(const uint8_t* data, size_t len, uint8_t* out, size_t out_len) {
    // Allocation-free variant: squeeze directly into caller's buffer.
    static constexpr size_t RATE = 136;
    Sponge s(RATE);
    s.absorb(data, len);
    s.finalize(DOMAIN_SHAKE);
    // Inline squeeze to avoid vector allocation
    for (size_t i = 0; i < out_len; ++i) {
        if (s.pos == RATE) { keccak_f1600(s.state); s.pos = 0; }
        out[i] = read_byte(s.state, s.pos++);
    }
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
