// SPHINCS+ / SLH-DSA-SHAKE-128s — functional test suite
//
// Tests the full sign/verify round trip and rejection of tampered data,
// plus NIST ACVP known-answer vectors for keygen and signing.
// Key generation and signing are deterministic when opt_rand is supplied.
#include "sphincs.h"
#include "sphincs_kat_vectors.h"
#include "../sha3/sha3.h"
#include <algorithm>
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

static std::vector<uint8_t> from_hex(const std::string& s) {
    std::vector<uint8_t> v;
    v.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        auto nib = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            return static_cast<uint8_t>(c - 'a' + 10);
        };
        v.push_back(static_cast<uint8_t>((nib(s[i]) << 4) | nib(s[i+1])));
    }
    return v;
}

// ── NIST ACVP known-answer tests ─────────────────────────────────────────────

static void test_kat_keygen() {
    for (const auto& tc : sphincs_kat::KEYGEN) {
        std::array<uint8_t, 3 * sphincs::N> seed{};
        auto sk_seed = from_hex(tc.sk_seed);
        auto sk_prf  = from_hex(tc.sk_prf);
        auto pk_seed = from_hex(tc.pk_seed);
        std::copy(sk_seed.begin(), sk_seed.end(), seed.begin());
        std::copy(sk_prf.begin(),  sk_prf.end(),  seed.begin() + sphincs::N);
        std::copy(pk_seed.begin(), pk_seed.end(), seed.begin() + 2 * sphincs::N);

        auto kp = sphincs::keygen(seed);
        auto expected = from_hex(tc.pk);
        bool ok = std::equal(kp.pk.pk_seed.begin(), kp.pk.pk_seed.end(), expected.begin()) &&
                  std::equal(kp.pk.pk_root.begin(), kp.pk.pk_root.end(), expected.begin() + sphincs::N);
        check("KAT keygen tcId=" + std::to_string(tc.tc_id), ok);
    }
}

static void test_kat_sign() {
    for (const auto& tc : sphincs_kat::SIGN) {
        auto skb = from_hex(tc.sk);
        sphincs::SecretKey sk{};
        std::copy(skb.begin(),      skb.begin() + 16, sk.sk_seed.begin());
        std::copy(skb.begin() + 16, skb.begin() + 32, sk.sk_prf.begin());
        std::copy(skb.begin() + 32, skb.begin() + 48, sk.pk_seed.begin());
        std::copy(skb.begin() + 48, skb.begin() + 64, sk.pk_root.begin());
        sphincs::PublicKey pk{sk.pk_seed, sk.pk_root};

        // FIPS 205 deterministic variant: opt_rand = PK.seed
        auto opt_rand = tc.opt_rand ? from_hex(tc.opt_rand)
                                    : std::vector<uint8_t>(sk.pk_seed.begin(), sk.pk_seed.end());
        auto msg = from_hex(tc.message);

        auto sig = sphincs::sign(msg.data(), msg.size(), sk, opt_rand.data());
        auto digest = sha3::sha3_256(sig.data(), sig.size());
        std::string label = "KAT sign tgId=" + std::to_string(tc.tg_id) +
                            " tcId=" + std::to_string(tc.tc_id);
        check(label + " signature matches", sha3::to_hex(digest.data(), digest.size()) == tc.sig_sha3_256);
        check(label + " verifies", sphincs::verify(msg.data(), msg.size(), sig, pk));
    }
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
    std::cout << "NIST ACVP vectors (SLH-DSA-SHAKE-128s)...\n";
    test_kat_keygen();
    test_kat_sign();
    std::cout << "\n";

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

    // ── Multi-block message (exceeds the SHAKE256 rate) ───────────────────────
    {
        std::vector<uint8_t> msg1k(1024);
        for (size_t i = 0; i < msg1k.size(); ++i) msg1k[i] = static_cast<uint8_t>(i);
        test_roundtrip("1 KiB msg:", seed, msg1k, zero_rand);
    }

    std::cout << "\n" << passed << " passed, " << failed << " failed.\n";
    return failed > 0 ? 1 : 0;
}
