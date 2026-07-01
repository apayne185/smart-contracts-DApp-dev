// ML-KEM-512 functional test suite
//
// Tests the full keygen / encaps / decaps pipeline and rejection behaviour.
#include "mlkem.h"
#include <array>
#include <cassert>
#include <iostream>
#include <string>

static int passed = 0, failed = 0;

static void check(const std::string& label, bool ok) {
    if (ok) { std::cout << "PASS  " << label << "\n"; ++passed; }
    else     { std::cout << "FAIL  " << label << "\n"; ++failed; }
}

static std::string hex(const uint8_t* p, size_t n) {
    std::string s; s.reserve(2*n);
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) { s += H[p[i]>>4]; s += H[p[i]&0xf]; }
    return s;
}

int main() {
    // Fixed seeds for deterministic tests
    std::array<uint8_t, 64> seed{};
    for (size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<uint8_t>(i + 1);

    std::array<uint8_t, 32> m{};
    for (size_t i = 0; i < m.size(); ++i) m[i] = static_cast<uint8_t>(i + 0x10);

    std::cout << "Generating key pair (ML-KEM-512)...\n";
    auto kp = mlkem::keygen(seed);

    bool ek_nonzero = false, dk_nonzero = false;
    for (auto b : kp.ek) ek_nonzero |= (b != 0);
    for (auto b : kp.dk) dk_nonzero |= (b != 0);
    check("keygen: ek non-zero", ek_nonzero);
    check("keygen: dk non-zero", dk_nonzero);
    std::cout << "  ek[0..15] = " << hex(kp.ek.data(), 16) << "\n";

    // ── Round-trip ────────────────────────────────────────────────────────────
    std::cout << "\nEncapsulating...\n";
    auto [ss_enc, ct] = mlkem::encaps(kp.ek, m);
    check("encaps: ct length",   ct.size()     == mlkem::CT_BYTES);
    check("encaps: ss non-zero", ss_enc != mlkem::SharedSecret{});
    std::cout << "  ss (enc) = " << hex(ss_enc.data(), 16) << "...\n";

    auto ss_dec = mlkem::decaps(kp.dk, ct);
    check("decaps: ss matches encaps", ss_dec == ss_enc);

    // ── Tampered ciphertext → implicit rejection ───────────────────────────
    {
        auto ct_bad = ct;
        ct_bad[0] ^= 0xFF;
        auto ss_bad = mlkem::decaps(kp.dk, ct_bad);
        check("decaps: tampered ct → different ss", ss_bad != ss_enc);
        check("decaps: tampered ct → non-zero ss",  ss_bad != mlkem::SharedSecret{});
    }

    // ── Wrong decap key → different ss ────────────────────────────────────
    {
        std::array<uint8_t, 64> seed2{};
        for (size_t i = 0; i < seed2.size(); ++i) seed2[i] = static_cast<uint8_t>(i + 0x80);
        auto kp2 = mlkem::keygen(seed2);
        auto ss_wrong = mlkem::decaps(kp2.dk, ct);
        check("decaps: wrong dk → different ss", ss_wrong != ss_enc);
    }

    // ── Determinism ───────────────────────────────────────────────────────
    {
        auto [ss_a, ct_a] = mlkem::encaps(kp.ek, m);
        auto [ss_b, ct_b] = mlkem::encaps(kp.ek, m);
        check("encaps: deterministic with same m", ct_a == ct_b && ss_a == ss_b);

        std::array<uint8_t, 32> m2{};
        m2[0] = 0xFF;
        auto [ss_c, ct_c] = mlkem::encaps(kp.ek, m2);
        check("encaps: different m → different ct", ct_c != ct_a);
        auto ss_dec_c = mlkem::decaps(kp.dk, ct_c);
        check("decaps: alt-m round-trip", ss_dec_c == ss_c);
    }

    // ── Second independent key pair ────────────────────────────────────────
    {
        std::array<uint8_t, 64> seed3{};
        for (size_t i = 0; i < seed3.size(); ++i) seed3[i] = static_cast<uint8_t>(i + 0x40);
        auto kp3 = mlkem::keygen(seed3);
        std::array<uint8_t, 32> m3{};
        m3[0] = 0xAB;
        auto [ss3, ct3] = mlkem::encaps(kp3.ek, m3);
        auto ss3d = mlkem::decaps(kp3.dk, ct3);
        check("second key pair round-trip", ss3 == ss3d);
    }

    std::cout << "\n" << passed << " passed, " << failed << " failed.\n";
    return failed > 0 ? 1 : 0;
}
