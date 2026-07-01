// ML-KEM-512 functional test suite
//
// Tests the full keygen / encaps / decaps pipeline and rejection behaviour.
#include "mlkem.h"
#include <algorithm>
#include <array>
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

static int passed = 0, failed = 0;

static void check(const std::string& label, bool ok) {
    if (ok) { std::cout << "PASS  " << label << "\n"; ++passed; }
    else     { std::cout << "FAIL  " << label << "\n"; ++failed; }
}

static std::vector<uint8_t> from_hex(const std::string& s) {
    std::vector<uint8_t> v;
    v.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        auto nib = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            return static_cast<uint8_t>(c - 'a' + 10);
        };
        v.push_back(static_cast<uint8_t>((nib(s[i]) << 4) | nib(s[i+1])));
    }
    return v;
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

    // ── Known-Answer Tests (NIST FIPS 203 vectors) ────────────────────────────
    // keygen inputs/ek: NIST ACVP ML-KEM-keyGen-FIPS203 tcId=1.
    // ct/ss: golden values from this implementation (no independent encapDecap
    //        vector available for FIPS 203 final; round-trip tests validate
    //        decaps correctness independently above).
    std::cout << "\nKnown-Answer Tests (NIST ACVP keygen + golden encaps vectors)...\n";
    {
        // Inputs (d || z = 64-byte seed; m = encapsulation randomness)
        auto d  = from_hex("47b893474672ba92e4b12ee44fb32953af8e8503b5fb471d1614fb8a021a660a");
        auto z  = from_hex("1f8cb39e9e30bc458a0dc5408884b1187fb217018df760fa57317703b844a0a9");
        auto mv = from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        // Expected encapsulation key (800 bytes) — validated against NIST ACVP tcId=1
        auto exp_ek = from_hex(
            "28266a088b3482439bca01afb7ca5c6136a979b5159985a9484b36b679a5f7b9"
            "819eb63577891f7bb9cb98413ccc434adc79a16d6ab3076569ce6291c59b5d64"
            "612a7fb0c15013200bc8bebb03a570174b5e4363aed86eb02a220d281fb5457f"
            "0a549fc5051d49a6b2015259a2c3084f405e1769952260675586a58490405927"
            "5a265234ef3abf88c171a80898fc783358bbc9803c8789027d917c9ebacbc568"
            "cc18de84c85454b94249586c0c6e2b8a16fa789c51212dd1728ee9b8c6c40528"
            "bf93826fa82368419623032af27b5694305816811d3ca85805100e9c1a9621e5"
            "089e54cb47f5a8fea0b49ef81c6b5187f48924c7947d6b61697a4a8a18452ef8"
            "03336ad4be503275bcacc03c181405f7b1dc9b47fb169eb37bbe27e29c763a4e"
            "52b9a42520388cf09b8edbcdf41ccf6537190e6156c37cc1aac63c0f90ce78d0"
            "b9b190c548d71b6f26cc8f585ea14004b5b30aaa100b2adc1263828833b24e46"
            "163b41446f98c882092a39941867b80632e2097674a793935227db0b8577e03a"
            "69c50a514c7473c892e3fba7c4316bdabc952a70644176687d4191323bad93d8"
            "5a3ca250868c0747e6c44f6126c874afbec0bdd4503cb2c59a69816e7d410994"
            "1467579a1ffe6a4f50fa379051729dab6e2f61432f15be67d667c7cc1054742b"
            "2b953078a5cf88d9133087309d88c61da240d99c59137329907b47865321ecd5"
            "564e987333b4cb607b0afca86769dc95b2f921357213fcb80c3b152918e9bab2"
            "228c0a1b77897ac68ce55088165f87f397da9790873b62c5383c0ccc370f0267"
            "cbe195651ccf336182c22ac3924b76c9e779b7a271d166b6d24b84242b7e73cc"
            "723f764039f6c851744034c3304db0c091a5764fdc9d593556ff734b82a87ccb"
            "c38ca99564d988bbd2d1bf071bb160722d365104fb27610651a8ed817f2742a6"
            "b5a1273a61acaf4460b0ab1456a9922351400a1c7d95d856d6e3370622c9c416"
            "4bc6b401435624a98b95caeb274f34ce92038d785068cdd8cf44c38d84acb2c4"
            "66a2756c870ee78c26e738cc451002304eb8c90ab24b6463eb124d779f937a2e"
            "3692611d2e34d57b36cc4b2cd3b31ff485c6684d408b972e0d5ca7d2224aae4e");

        // Expected ciphertext and shared secret (golden values from this implementation)
        auto exp_ct = from_hex(
            "21bfa9f1a45569ed7ce8f87db6256f9efcbbd7c683daac5b8c8c6c666c57919a"
            "0f6c2e3bd7539d1d5e0b197c3afff348d8127da2e0ee2a23ca2e48551ec424ad"
            "f2d08718597c30ac485777eac7e248603e5133b167f6124fbfb5f5dde8aee505"
            "3366c8a6e35b7b036f8b4a30dc2c7c464ac7173445c4f7417aee42c53e9d0a69"
            "b2bd02e7b48c9bcc152afde313b0fb0c2112c224790ec9e6a52663be762269b1"
            "1811463945805a032a79225c570b8e7768ef9c66da9667f97f8b1c833f79ea16"
            "bbb34c247e2d21045a120a1eb0f92064bad59a72fae9a181ac3bac86c31f7abb"
            "876dea62fca1a072f2cfb6288853480e60414f960703aabb7994c82795c396e3"
            "dceb5f426f3c2c16a42cef6edfb271d22103ab09ff304363a9b3856aa9559f9e"
            "f4ed5c3a22341eec532a3c3a1e6166542768f7f21b820b561553b1a972095419"
            "66045b6c44950d5f9b0b7edc3d4de30620d4adf9376c68e78265fd4d04525a74"
            "f7e75d069f2df184ba3f584e5906ef0581b9d0f423e169740bbe432635f8511c"
            "62de930818abbce1030e7fe962f821e7befd9084edd786ae5aa57106fad6ebff"
            "a486ddfac3c51db689e1d81c9509b665de1c39090c8dfe4482b49e5559b89746"
            "5fecd087f3a06e4ca31dd31fee7981bf213ebf73eaef41b9ab392304eb6e5f30"
            "71ce18bb2316d95ba9fe98c985cd1a8076fe72a0523cc8d9ca7d5d0fdbc73d31"
            "1980446e38d4c335193999b120c4f985a8797d0c11d94895c73d45cc8c671c70"
            "5e01dc7916ee629976ac90d6fc67c018c72a0065d0721878185eccc7c4f34887"
            "42cfc113b4356a484e1e012363323b2b5222a8e13d2efbba2cbe7cff2bdd355c"
            "eb85c77a5b892a3ea65f9534e8afc17c18aea7000aa02bceda135a7968e3be1b"
            "13942b6cd41fcae96c6e61041de0a581d4de40a8d67c3d97f31f2fc2577106d0"
            "bc8ccc9a40e7c418db86d9b2ef0945ccaf4e0e4a6d61fa213299ba425307a1b3"
            "ef030f82430e0704dc024d6e39044a885228d1a6e18ac095cafc2fc1ac0af053"
            "9de975ccd95391658846246f9181a3781885cff71c600f67543146375052ca1b");

        // Expected shared secret (32 bytes)
        auto exp_ss = from_hex("1f9d8a24f5757dc70746d2d1f48c016fc8213bd510b174171b73741bc60555d6");

        // Build typed inputs
        std::array<uint8_t, 64> seed;
        std::copy(d.begin(), d.end(), seed.begin());
        std::copy(z.begin(), z.end(), seed.begin() + 32);
        std::array<uint8_t, 32> msg;
        std::copy(mv.begin(), mv.end(), msg.begin());

        auto kp_kat = mlkem::keygen(seed);
        check("KAT: keygen ek matches NIST ACVP tcId=1",
              std::equal(exp_ek.begin(), exp_ek.end(), kp_kat.ek.begin()));

        auto [ss_kat, ct_kat] = mlkem::encaps(kp_kat.ek, msg);
        check("KAT: encaps ct matches golden vector",
              std::equal(exp_ct.begin(), exp_ct.end(), ct_kat.begin()));
        check("KAT: encaps ss matches golden vector",
              std::equal(exp_ss.begin(), exp_ss.end(), ss_kat.begin()));

        mlkem::Ciphertext ct_known;
        std::copy(exp_ct.begin(), exp_ct.end(), ct_known.begin());
        auto ss_dec_kat = mlkem::decaps(kp_kat.dk, ct_known);
        check("KAT: decaps ss matches golden vector",
              std::equal(exp_ss.begin(), exp_ss.end(), ss_dec_kat.begin()));
    }

    std::cout << "\n" << passed << " passed, " << failed << " failed.\n";
    return failed > 0 ? 1 : 0;
}
