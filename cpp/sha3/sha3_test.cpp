// SHA-3 / Keccak known-answer tests — NIST FIPS 202 vectors.
// Covers SHA3-256, SHA3-512, SHAKE128, SHAKE256.
// Exits 0 on all-pass, 1 on any failure.
#include "sha3.h"
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

struct Vec256 { std::string input; std::string expected; };
struct Vec512 { std::string input; std::string expected; };
struct VecXOF { std::string input; size_t outbytes; std::string expected; };

// ---------------------------------------------------------------------------
// FIPS 202 known-answer test vectors (verified against Python hashlib)
// ---------------------------------------------------------------------------

static const std::vector<Vec256> SHA3_256_VECTORS = {
    { "",
      "a7ffc6f8bf1ed76651c14756a061d662"
      "f580ff4de43b49fa82d80a4b80f8434a" },
    { "abc",
      "3a985da74fe225b2045c172d6bd390bd"
      "855f086e3e9d525b46bfe24511431532" },
    // FIPS 202 §A.1 — 448-bit message
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "41c0dba2a9d6240849100376a8235e2c"
      "82e1b9998a999e21db32dd97496d3376" },
    // Block-boundary: 135 bytes fills exactly one SHA3-256 rate block before padding
    { std::string(135, 'a'),
      "8094bb53c44cfb1e67b7c30447f9a1c3"
      "3696d2463ecc1d9c92538913392843c9" },
    // Two-block message: 136 bytes forces a second block
    { std::string(136, 'a'),
      "3fc5559f14db8e453a0a3091edbd2bc2"
      "5e11528d81c66fa570a4efdcc2695ee1" },
};

static const std::vector<Vec512> SHA3_512_VECTORS = {
    { "",
      "a69f73cca23a9ac5c8b567dc185a756e"
      "97c982164fe25859e0d1dcc1475c80a6"
      "15b2123af1f5f94c11e3e9402c3ac558"
      "f500199d95b6d3e301758586281dcd26" },
    { "abc",
      "b751850b1a57168a5693cd924b6b096e"
      "08f621827444f70d884f5d0240d2712e"
      "10e116e9192af3c91a7ec57647e39340"
      "57340b4cf408d5a56592f8274eec53f0" },
};

static const std::vector<VecXOF> SHAKE128_VECTORS = {
    { "", 32,
      "7f9c2ba4e88f827d616045507605853e"
      "d73b8093f6efbc88eb1a6eacfa66ef26" },
};

static const std::vector<VecXOF> SHAKE256_VECTORS = {
    { "abc", 64,
      "483366601360a8771c6863080cc4114d"
      "8db44530f8f1e1ee4f94ea37e78b5739"
      "d5a15bef186a5386c75744c0527e1faa"
      "9f8726e462a12a4feb06bd8801e751e4" },
};

// ---------------------------------------------------------------------------

static int passed = 0, failed = 0;

static void check(const std::string& label, const std::string& got, const std::string& expected) {
    if (got == expected) {
        std::cout << "PASS  " << label << "\n";
        ++passed;
    } else {
        std::cout << "FAIL  " << label << "\n"
                  << "      expected: " << expected << "\n"
                  << "      got:      " << got      << "\n";
        ++failed;
    }
}

int main() {
    for (const auto& v : SHA3_256_VECTORS) {
        auto tag = "sha3_256(\"" + v.input.substr(0, 16) +
                   (v.input.size() > 16 ? "..." : "") + "\")";
        check(tag, sha3::to_hex(sha3::sha3_256(v.input)), v.expected);
    }

    for (const auto& v : SHA3_512_VECTORS) {
        auto tag = "sha3_512(\"" + v.input.substr(0, 16) +
                   (v.input.size() > 16 ? "..." : "") + "\")";
        check(tag, sha3::to_hex(sha3::sha3_512(v.input)), v.expected);
    }

    for (const auto& v : SHAKE128_VECTORS) {
        auto tag = "shake128(\"" + v.input.substr(0, 16) + "\", " +
                   std::to_string(v.outbytes) + ")";
        check(tag, sha3::to_hex(sha3::shake128(v.input, v.outbytes)), v.expected);
    }

    for (const auto& v : SHAKE256_VECTORS) {
        auto tag = "shake256(\"" + v.input.substr(0, 16) + "\", " +
                   std::to_string(v.outbytes) + ")";
        check(tag, sha3::to_hex(sha3::shake256(v.input, v.outbytes)), v.expected);
    }

    std::cout << "\n" << passed << " passed, " << failed << " failed.\n";
    return failed > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
