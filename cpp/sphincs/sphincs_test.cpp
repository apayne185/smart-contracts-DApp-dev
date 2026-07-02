// SPHINCS+ / SLH-DSA-SHAKE-128s — functional test suite
//
// Tests the full sign/verify round trip and rejection of tampered data.
// Key generation and signing are deterministic when opt_rand is supplied.
#include "sphincs.h"
#include "../sha3/sha3.h"
#include <array>
#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

static int passed = 0, failed = 0;

static void check(const std::string& label, bool ok) {
    if (ok) { std::cout << "PASS  " << label << "\n"; ++passed; }
    else     { std::cout << "FAIL  " << label << "\n"; ++failed; }
}

// ── Internal types replicated for unit tests ─────────────────────────────────
// (We test via the public API + a few small inline helpers here.)

using Bytes_N = std::array<uint8_t, sphincs::N>;

static std::string hex(const uint8_t* p, size_t n) {
    std::string s; s.reserve(2*n);
    static const char H[] = "0123456789abcdef";
    for (size_t i=0;i<n;++i) { s+=H[p[i]>>4]; s+=H[p[i]&0xf]; }
    return s;
}

// ── Component smoke tests ─────────────────────────────────────────────────────

// Verify that keygen, sign, and verify are self-consistent by checking
// that round-tripping a message produces the same PK root:
// 1. keygen with seed A
// 2. sign with SK_A + opt_rand = 0
// 3. verify with PK_A
// This tests the full pipeline end-to-end.

static void test_roundtrip(const std::string& label,
                            const std::array<uint8_t, 3*sphincs::N>& seed,
                            const std::vector<uint8_t>& msg,
                            const std::array<uint8_t, sphincs::N>& opt_rand)
{
    auto kp  = sphincs::keygen(seed);
    auto sig = sphincs::sign(msg.data(), msg.size(), kp.sk, opt_rand.data());
    check(label + " sig_len",  sig.size() == sphincs::SIG_BYTES);
    check(label + " verify",   sphincs::verify(msg.data(), msg.size(), sig, kp.pk));
}

// ── Main ─────────────────────────────────────────────────────────────────────

int main() {
    // ── Fixed seed ────────────────────────────────────────────────────────────
    std::array<uint8_t, 3*sphincs::N> seed{};
    for (size_t i=0; i<seed.size(); ++i) seed[i] = static_cast<uint8_t>(i+1);

    std::cout << "Generating key pair (SLH-DSA-SHAKE-128s)...\n";
    auto kp = sphincs::keygen(seed);

    bool pk_nonzero = false;
    for (auto b : kp.pk.pk_root) pk_nonzero |= (b != 0);
    check("keygen: pk_root non-zero", pk_nonzero);

    // Print PK.root so we can visually confirm
    std::cout << "  PK.root = " << hex(kp.pk.pk_root.data(), sphincs::N) << "\n";

    // ── Sign a short message ──────────────────────────────────────────────────
    std::cout << "\nSigning 5-byte message...\n";
    std::vector<uint8_t> msg5 = {'h','e','l','l','o'};
    std::array<uint8_t, sphincs::N> zero_rand{};
    auto sig5 = sphincs::sign(msg5.data(), msg5.size(), kp.sk, zero_rand.data());

    check("sign: sig length",           sig5.size() == sphincs::SIG_BYTES);
    check("verify: 5-byte msg valid",   sphincs::verify(msg5.data(), msg5.size(), sig5, kp.pk));

    // ── Tamper tests ──────────────────────────────────────────────────────────
    {
        auto msg_bad = msg5; msg_bad[0] ^= 1;
        check("verify: tampered msg rejected",
              !sphincs::verify(msg_bad.data(), msg_bad.size(), sig5, kp.pk));
    }
    {
        auto sig_bad = sig5; sig_bad[0] ^= 1;
        check("verify: tampered R rejected",
              !sphincs::verify(msg5.data(), msg5.size(), sig_bad, kp.pk));
    }
    {
        auto sig_bad = sig5; sig_bad[sig5.size()-1] ^= 1;
        check("verify: tampered HT tail rejected",
              !sphincs::verify(msg5.data(), msg5.size(), sig_bad, kp.pk));
    }
    {
        std::array<uint8_t, 3*sphincs::N> seed2{};
        for (size_t i=0;i<seed2.size();++i) seed2[i] = static_cast<uint8_t>(i+0x80);
        auto kp2 = sphincs::keygen(seed2);
        check("verify: wrong PK rejected",
              !sphincs::verify(msg5.data(), msg5.size(), sig5, kp2.pk));
    }

    // ── Determinism ───────────────────────────────────────────────────────────
    {
        auto sig_a = sphincs::sign(msg5.data(), msg5.size(), kp.sk, zero_rand.data());
        auto sig_b = sphincs::sign(msg5.data(), msg5.size(), kp.sk, zero_rand.data());
        check("sign: deterministic with same opt_rand", sig_a == sig_b);

        std::array<uint8_t, sphincs::N> r2{}; r2[0] = 0xFF;
        auto sig_c = sphincs::sign(msg5.data(), msg5.size(), kp.sk, r2.data());
        check("sign: different opt_rand → different sig", sig_a != sig_c);
        check("verify: alt-rand sig valid",
              sphincs::verify(msg5.data(), msg5.size(), sig_c, kp.pk));
    }

    // ── Empty message ─────────────────────────────────────────────────────────
    {
        std::vector<uint8_t> empty;
        auto sig_e = sphincs::sign(empty.data(), 0, kp.sk, zero_rand.data());
        check("verify: empty msg round-trip",
              sphincs::verify(empty.data(), 0, sig_e, kp.pk));
    }

    std::cout << "\n" << passed << " passed, " << failed << " failed.\n";
    return failed > 0 ? 1 : 0;
}
