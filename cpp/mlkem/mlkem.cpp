// ML-KEM / CRYSTALS-Kyber implementation (NIST FIPS 203)
//
// Algorithm references:
//   §4   Auxiliary functions (ByteEncode, ByteDecode, Compress, Decompress)
//   §4.3 NTT and InvNTT
//   §5   K-PKE (the underlying CPA-secure encryption)
//   §6   ML-KEM (the CCA-secure KEM built on K-PKE)
//
// Hash functions (§4.1, SHAKE variant):
//   G  = SHA3-512   (key expansion, encaps randomness)
//   H  = SHA3-256   (public-key hash in dk)
//   J  = SHAKE256   (implicit rejection value)
//   PRF_η = SHAKE256(s ∥ b, 64η)  (noise sampling)
//   XOF   = SHAKE128(ρ ∥ i ∥ j, …)  (matrix expansion)
#include "mlkem.h"
#include "../sha3/sha3.h"
#include <array>
#include <cassert>
#include <cstring>
#include <stdexcept>

namespace mlkem {

// Zero a buffer in a way the compiler cannot optimise away.
static void secure_zero(void* p, size_t n) {
    volatile uint8_t* vp = static_cast<volatile uint8_t*>(p);
    for (size_t i = 0; i < n; ++i) vp[i] = 0;
}

static_assert(K*384 + 32          == EK_BYTES,  "EK_BYTES mismatch");
static_assert(K*384 + EK_BYTES + 64 == DK_BYTES, "DK_BYTES mismatch");
static_assert(K*DU*N/8 + DV*N/8   == CT_BYTES,  "CT_BYTES mismatch");

// ── Internal polynomial type ──────────────────────────────────────────────────

struct Poly    { int16_t c[N] = {}; };
using  PolyVec = std::array<Poly, K>;
using  PolyMat = std::array<PolyVec, K>;

// ── Modular arithmetic ────────────────────────────────────────────────────────

// Reduce x to [0, Q-1] without data-dependent branches.
// x % Q lies in (-(Q-1), Q-1); the arithmetic right-shift produces a mask
// of all-ones when the remainder is negative, adding Q only in that case.
static inline int16_t rq(int32_t x) {
    x %= Q;
    x += Q & (x >> 31);   // add Q iff x is negative
    return static_cast<int16_t>(x);
}

// ── NTT zeta table ────────────────────────────────────────────────────────────
//
// The NTT in ML-KEM is a 7-layer Cooley-Tukey butterfly over Z_q[X]/(X^256+1).
// ζ = 17 is a primitive 256th root of unity mod q=3329.
// For layer-k the twiddle factor is ζ^{BitRev7(k)}.
// BitRev7 reverses the 7-bit representation of k.

static constexpr int32_t powmod_ct(int32_t b, int32_t e, int32_t m) {
    int32_t r = 1; b %= m;
    for (; e > 0; e >>= 1) { if (e & 1) r = (int64_t)r*b%m; b = (int64_t)b*b%m; }
    return r;
}
static constexpr int bitrev7(int x) {
    int r = 0;
    for (int i = 0; i < 7; ++i, x >>= 1) r = (r<<1)|(x&1);
    return r;
}

// ZETAS[i] = 17^{bitrev7(i+1)} mod Q   for i = 0..126  (NTT layers k=1..127)
// MUL_GAMMA[i] = 17^{2*bitrev7(i)+1} mod Q  for i = 0..127  (BaseCaseMul)
static constexpr auto make_zetas() {
    std::array<int16_t, 128> z{};
    for (int k = 1; k <= 128; ++k)
        z[k-1] = static_cast<int16_t>(powmod_ct(17, bitrev7(k), Q));
    return z;
}
static constexpr auto make_gammas() {
    std::array<int16_t, 128> g{};
    for (int i = 0; i < 128; ++i)
        g[i] = static_cast<int16_t>(powmod_ct(17, 2*bitrev7(i)+1, Q));
    return g;
}
static constexpr auto ZETAS  = make_zetas();
static constexpr auto GAMMAS = make_gammas();

// ── NTT (Algorithm 9) ─────────────────────────────────────────────────────────

static void ntt(Poly& f) {
    int k = 0;
    for (int len = 128; len >= 2; len >>= 1) {
        for (int start = 0; start < N; start += 2*len) {
            int16_t zeta = ZETAS[k++];
            for (int j = start; j < start + len; ++j) {
                int16_t t = rq((int32_t)zeta * f.c[j+len]);
                f.c[j+len] = rq(f.c[j] - t);
                f.c[j]     = rq(f.c[j] + t);
            }
        }
    }
}

// ── InvNTT (Algorithm 10) ─────────────────────────────────────────────────────

static void intt(Poly& f) {
    // 128^{-1} mod Q = 3303  (since 128*3303 ≡ 1 mod 3329)
    static constexpr int16_t INV128 = 3303;
    int k = 126;
    for (int len = 2; len <= 128; len <<= 1) {
        for (int start = 0; start < N; start += 2*len) {
            int16_t zeta = ZETAS[k--];
            for (int j = start; j < start + len; ++j) {
                int16_t t   = f.c[j];
                f.c[j]      = rq(t + f.c[j+len]);
                f.c[j+len]  = rq((int32_t)zeta * rq(f.c[j+len] - t));
            }
        }
    }
    for (int i = 0; i < N; ++i)
        f.c[i] = rq((int32_t)INV128 * f.c[i]);
}

// ── BaseCaseMul (Algorithm 11) + MultiplyNTTs (Algorithm 12) ─────────────────

// Multiply two degree-1 polynomials in Z_q[X]/(X^2 - gamma)
static void base_mul(int16_t& r0, int16_t& r1,
                     int16_t a0, int16_t a1,
                     int16_t b0, int16_t b1, int16_t gamma)
{
    // Reduce a1*b1 before multiplying by gamma: a1*b1 can reach (Q-1)^2 ≈ 11M;
    // without pre-reduction, *gamma pushes the value past INT32_MAX.
    int32_t a1b1 = rq((int32_t)a1 * b1);
    r0 = rq((int32_t)a0*b0 + a1b1 * gamma);
    r1 = rq((int32_t)a0*b1 + (int32_t)a1*b0);
}

// Pointwise multiplication of two NTT-domain polynomials; result added to acc
static void poly_mul_acc(Poly& acc, const Poly& a, const Poly& b) {
    for (int i = 0; i < 128; ++i) {
        int16_t r0, r1;
        base_mul(r0, r1,
                 a.c[2*i], a.c[2*i+1],
                 b.c[2*i], b.c[2*i+1],
                 GAMMAS[i]);
        acc.c[2*i]   = rq(acc.c[2*i]   + r0);
        acc.c[2*i+1] = rq(acc.c[2*i+1] + r1);
    }
}

// ── Polynomial / vector helpers ───────────────────────────────────────────────

static Poly poly_add(const Poly& a, const Poly& b) {
    Poly r;
    for (int i = 0; i < N; ++i) r.c[i] = rq(a.c[i] + b.c[i]);
    return r;
}
static Poly poly_sub(const Poly& a, const Poly& b) {
    Poly r;
    for (int i = 0; i < N; ++i) r.c[i] = rq(a.c[i] - b.c[i]);
    return r;
}

// result[i] = sum_j mat[i][j] * vec[j]  (all in NTT domain, add into acc)
static PolyVec mat_vec_mul(const PolyMat& mat, const PolyVec& vec) {
    PolyVec r{};
    for (int i = 0; i < K; ++i)
        for (int j = 0; j < K; ++j)
            poly_mul_acc(r[i], mat[i][j], vec[j]);
    return r;
}

// ── Encoding / decoding (§4.2) ────────────────────────────────────────────────
//
// ByteEncode_d: pack 256 d-bit integers (little-endian) into 32*d bytes.
// ByteDecode_d: inverse.

static void byte_encode(uint8_t* out, const Poly& p, int d) {
    // Bit budget: N*d bits = 32*d bytes
    uint32_t buf = 0;
    int      bits = 0;
    int      bi   = 0;
    uint32_t mask = (1u << d) - 1;
    for (int i = 0; i < N; ++i) {
        buf  |= static_cast<uint32_t>(p.c[i] & mask) << bits;
        bits += d;
        while (bits >= 8) {
            out[bi++] = static_cast<uint8_t>(buf);
            buf  >>= 8;
            bits  -= 8;
        }
    }
}

static Poly byte_decode(const uint8_t* in, int d) {
    Poly p;
    uint32_t buf  = 0;
    int      bits = 0;
    int      bi   = 0;
    uint32_t mask = (1u << d) - 1;
    for (int i = 0; i < N; ++i) {
        while (bits < d) {
            buf  |= static_cast<uint32_t>(in[bi++]) << bits;
            bits += 8;
        }
        p.c[i] = static_cast<int16_t>(buf & mask);
        buf  >>= d;
        bits  -= d;
    }
    return p;
}

// ── Compress / Decompress (§4.2) ──────────────────────────────────────────────
//
// Compress_d(x)   = round(2^d / Q * x) mod 2^d
// Decompress_d(y) = round(Q / 2^d * y)

static Poly compress(const Poly& p, int d) {
    Poly r;
    // round(x * 2^d / Q) = floor((x * 2^d + Q/2) / Q) mod 2^d
    for (int i = 0; i < N; ++i) {
        int32_t x = static_cast<int32_t>(p.c[i]);
        r.c[i] = static_cast<int16_t>(((x << d) + Q/2) / Q % (1 << d));
    }
    return r;
}

static Poly decompress(const Poly& p, int d) {
    Poly r;
    for (int i = 0; i < N; ++i) {
        // round(y * Q / 2^d) = (y * Q + 2^{d-1}) >> d
        int32_t y = static_cast<int32_t>(p.c[i]);
        r.c[i] = static_cast<int16_t>((y * Q + (1 << (d-1))) >> d);
    }
    return r;
}

// ── Sampling ──────────────────────────────────────────────────────────────────

// SampleNTT (Algorithm 7): generate a uniform NTT-domain polynomial from XOF.
// Puts first_arg at seed[32] and second_arg at seed[33] — callers control byte
// order.  Keygen passes (j, i) to build A[i][j] = SampleNTT(ρ, j, i) per FIPS
// 203 Alg 13; encrypt passes (i, j) for the transpose A^T per Alg 14.
static Poly sample_ntt(const uint8_t* rho, uint8_t i, uint8_t j) {
    // XOF = SHAKE128(ρ ∥ first_arg ∥ second_arg, outbytes)
    // Each 3-byte group yields two 12-bit candidates; ~500 bytes is always enough.
    uint8_t seed[34];
    memcpy(seed, rho, 32);
    seed[32] = i;
    seed[33] = j;

    // 504 bytes = 168 three-byte groups → 336 candidates.
    // Each candidate is accepted with probability Q/4096 ≈ 81.3%.
    // P(< 256 accepted from 336) < 10^{-30}; the throw is a safety net only.
    // Callers must handle std::runtime_error if this is used in a library.
    constexpr size_t OUTBYTES = 504;
    uint8_t buf[OUTBYTES];
    sha3::shake128_into(seed, 34, buf, OUTBYTES);

    Poly a;
    int cnt = 0, bi = 0;
    while (cnt < N) {
        if (bi + 3 > (int)OUTBYTES)
            throw std::runtime_error("SampleNTT: XOF output exhausted");
        uint16_t d1 = buf[bi] | ((uint16_t)(buf[bi+1] & 0x0F) << 8);
        uint16_t d2 = (buf[bi+1] >> 4) | ((uint16_t)buf[bi+2] << 4);
        bi += 3;
        if (d1 < Q) a.c[cnt++] = static_cast<int16_t>(d1);
        if (d2 < Q && cnt < N) a.c[cnt++] = static_cast<int16_t>(d2);
    }
    return a;
}

// SamplePolyCBD_η (Algorithm 8): sample from centred binomial distribution.
// Input: buf of length 64*eta bytes (output of PRF_eta).
static Poly sample_cbd(const uint8_t* buf, int eta) {
    Poly f;
    for (int i = 0; i < N; ++i) {
        int a = 0, b = 0;
        for (int j = 0; j < eta; ++j) {
            int pos_a = 2*i*eta + j;
            int pos_b = 2*i*eta + eta + j;
            a += (buf[pos_a/8] >> (pos_a%8)) & 1;
            b += (buf[pos_b/8] >> (pos_b%8)) & 1;
        }
        f.c[i] = rq(a - b);
    }
    return f;
}

// PRF_η: SHAKE256(σ ∥ N_byte, 64*η)
static void prf(uint8_t* out, size_t outlen,
                const uint8_t* sigma, uint8_t n_byte)
{
    uint8_t seed[33];
    memcpy(seed, sigma, 32);
    seed[32] = n_byte;
    sha3::shake256_into(seed, 33, out, outlen);
}

// ── K-PKE inner encryption (§5) ───────────────────────────────────────────────

struct PKE_KeyPair {
    uint8_t ek[EK_BYTES];   // ByteEncode_12(t_hat) ∥ ρ
    uint8_t dk[K*384];      // ByteEncode_12(s_hat)
};

// Algorithm 13: K-PKE.KeyGen(d)
static PKE_KeyPair pke_keygen(const uint8_t* d) {
    // G(d ∥ k) → (ρ, σ)  where k=K as a single byte
    uint8_t g_in[33];
    memcpy(g_in, d, 32);
    g_in[32] = static_cast<uint8_t>(K);
    auto g_out = sha3::sha3_512(g_in, 33);
    const uint8_t* rho   = g_out.data();       // bytes 0..31
    const uint8_t* sigma = g_out.data() + 32;  // bytes 32..63

    // Expand matrix A_hat: A_hat[i][j] = SampleNTT(ρ, j, i)  (FIPS 203 §5.1 Alg 13)
    PolyMat A_hat;
    for (int i = 0; i < K; ++i)
        for (int j = 0; j < K; ++j)
            A_hat[i][j] = sample_ntt(rho, static_cast<uint8_t>(j),
                                          static_cast<uint8_t>(i));

    // Sample secret s and noise e via PRF_η1
    PolyVec s_hat, e_hat;
    uint8_t N_byte = 0;
    for (int i = 0; i < K; ++i, ++N_byte) {
        uint8_t prf_out[64 * ETA1];
        prf(prf_out, sizeof(prf_out), sigma, N_byte);
        s_hat[i] = sample_cbd(prf_out, ETA1);
        ntt(s_hat[i]);
        secure_zero(prf_out, sizeof(prf_out));
    }
    for (int i = 0; i < K; ++i, ++N_byte) {
        uint8_t prf_out[64 * ETA1];
        prf(prf_out, sizeof(prf_out), sigma, N_byte);
        e_hat[i] = sample_cbd(prf_out, ETA1);
        ntt(e_hat[i]);
        secure_zero(prf_out, sizeof(prf_out));
    }

    // t_hat = A_hat ∘ s_hat + e_hat
    PolyVec t_hat = mat_vec_mul(A_hat, s_hat);
    for (int i = 0; i < K; ++i)
        t_hat[i] = poly_add(t_hat[i], e_hat[i]);

    // Encode keys
    PKE_KeyPair kp;
    for (int i = 0; i < K; ++i)
        byte_encode(kp.ek + i*384, t_hat[i], 12);
    memcpy(kp.ek + K*384, rho, 32);             // ek = ByteEncode_12(t) ∥ ρ

    for (int i = 0; i < K; ++i)
        byte_encode(kp.dk + i*384, s_hat[i], 12);  // dk = ByteEncode_12(s)

    secure_zero(g_out.data(), g_out.size());     // wipe ρ∥σ from stack
    return kp;
}

// Algorithm 14: K-PKE.Encrypt(ek, m, r)
static void pke_encrypt(uint8_t* ct,
                        const uint8_t* ek,
                        const uint8_t* m,   // 32 bytes
                        const uint8_t* r)   // 32-byte randomness
{
    const uint8_t* rho = ek + K*384;   // last 32 bytes of ek

    // Decode t_hat from ek
    PolyVec t_hat;
    for (int i = 0; i < K; ++i)
        t_hat[i] = byte_decode(ek + i*384, 12);

    // Expand A^T: AT_hat[i][j] = A[j][i] = SampleNTT(ρ, i, j)  (FIPS 203 §5.2 Alg 14)
    PolyMat AT_hat;
    for (int i = 0; i < K; ++i)
        for (int j = 0; j < K; ++j)
            AT_hat[i][j] = sample_ntt(rho, static_cast<uint8_t>(i),
                                           static_cast<uint8_t>(j));

    // Sample r_vec, e1, e2 via PRF_η1/η2
    PolyVec r_hat, e1;
    uint8_t N_byte = 0;
    for (int i = 0; i < K; ++i, ++N_byte) {
        uint8_t prf_out[64 * ETA1];
        prf(prf_out, sizeof(prf_out), r, N_byte);
        r_hat[i] = sample_cbd(prf_out, ETA1);
        ntt(r_hat[i]);
        secure_zero(prf_out, sizeof(prf_out));
    }
    for (int i = 0; i < K; ++i, ++N_byte) {
        uint8_t prf_out[64 * ETA2];
        prf(prf_out, sizeof(prf_out), r, N_byte);
        e1[i] = sample_cbd(prf_out, ETA2);
        secure_zero(prf_out, sizeof(prf_out));
    }
    uint8_t e2_prf[64 * ETA2];
    prf(e2_prf, sizeof(e2_prf), r, N_byte);
    Poly e2 = sample_cbd(e2_prf, ETA2);
    secure_zero(e2_prf, sizeof(e2_prf));

    // u = NTT^{-1}(A^T ∘ r_hat) + e1
    PolyVec u = mat_vec_mul(AT_hat, r_hat);
    for (int i = 0; i < K; ++i) { intt(u[i]); u[i] = poly_add(u[i], e1[i]); }

    // mu = Decompress_1(ByteDecode_1(m))
    Poly mu = decompress(byte_decode(m, 1), 1);

    // v = NTT^{-1}(t_hat^T ∘ r_hat) + e2 + mu
    Poly v{};
    for (int i = 0; i < K; ++i) poly_mul_acc(v, t_hat[i], r_hat[i]);
    intt(v);
    v = poly_add(poly_add(v, e2), mu);

    // Encode: c1 = ByteEncode_du(Compress_du(u)), c2 = ByteEncode_dv(Compress_dv(v))
    constexpr int C1_POLY = DU * N / 8;   // 320 bytes per poly
    for (int i = 0; i < K; ++i)
        byte_encode(ct + i*C1_POLY, compress(u[i], DU), DU);
    byte_encode(ct + K*C1_POLY, compress(v, DV), DV);
}

// Algorithm 15: K-PKE.Decrypt(dk, c) → m (32 bytes)
static void pke_decrypt(uint8_t* m,
                        const uint8_t* dk,   // K*384 bytes
                        const uint8_t* ct)
{
    constexpr int C1_POLY = DU * N / 8;

    // Decode u and v
    PolyVec u;
    for (int i = 0; i < K; ++i)
        u[i] = decompress(byte_decode(ct + i*C1_POLY, DU), DU);
    Poly v = decompress(byte_decode(ct + K*C1_POLY, DV), DV);

    // Decode s_hat
    PolyVec s_hat;
    for (int i = 0; i < K; ++i)
        s_hat[i] = byte_decode(dk + i*384, 12);

    // w = v - NTT^{-1}(s_hat^T ∘ NTT(u))
    PolyVec u_hat = u;
    for (int i = 0; i < K; ++i) ntt(u_hat[i]);

    Poly w{};
    for (int i = 0; i < K; ++i) poly_mul_acc(w, s_hat[i], u_hat[i]);
    intt(w);
    w = poly_sub(v, w);

    // m = ByteEncode_1(Compress_1(w))
    byte_encode(m, compress(w, 1), 1);
}

// ── ML-KEM outer KEM (§6) ────────────────────────────────────────────────────

KeyPair keygen(const std::array<uint8_t, 64>& seed) {
    // d = seed[0..31], z = seed[32..63]
    const uint8_t* d = seed.data();
    const uint8_t* z = seed.data() + 32;

    auto pke_kp = pke_keygen(d);

    // H(ek) = SHA3-256(ek)
    auto h_ek = sha3::sha3_256(pke_kp.ek, EK_BYTES);

    KeyPair kp;
    // ek = ek_pke (identical layout)
    memcpy(kp.ek.data(), pke_kp.ek, EK_BYTES);
    // dk = dk_pke ∥ ek ∥ H(ek) ∥ z
    memcpy(kp.dk.data(),                 pke_kp.dk, K*384);
    memcpy(kp.dk.data() + K*384,         pke_kp.ek, EK_BYTES);
    memcpy(kp.dk.data() + K*384 + EK_BYTES, h_ek.data(), 32);
    memcpy(kp.dk.data() + K*384 + EK_BYTES + 32, z, 32);
    return kp;
}

std::pair<SharedSecret, Ciphertext>
encaps(const EncapKey& ek, const std::array<uint8_t, 32>& m) {
    // H(ek)
    auto h_ek = sha3::sha3_256(ek.data(), EK_BYTES);

    // (K_shared, r) = G(m ∥ H(ek))
    uint8_t g_in[64];
    memcpy(g_in,    m.data(),     32);
    memcpy(g_in+32, h_ek.data(), 32);
    auto g_out = sha3::sha3_512(g_in, 64);

    SharedSecret K_ss;
    memcpy(K_ss.data(), g_out.data(), 32);
    const uint8_t* r = g_out.data() + 32;

    Ciphertext ct;
    pke_encrypt(ct.data(), ek.data(), m.data(), r);
    return { K_ss, ct };
}

SharedSecret decaps(const DecapKey& dk, const Ciphertext& ct) {
    // Unpack dk layout: dk_pke | ek | h_ek | z
    const uint8_t* dk_pke = dk.data();
    const uint8_t* ek     = dk.data() + K*384;
    const uint8_t* h_ek   = dk.data() + K*384 + EK_BYTES;
    const uint8_t* z      = dk.data() + K*384 + EK_BYTES + 32;

    // Decrypt to recover m'
    uint8_t m_prime[32];
    pke_decrypt(m_prime, dk_pke, ct.data());

    // (K', r') = G(m' ∥ H(ek))
    uint8_t g_in[64];
    memcpy(g_in,    m_prime, 32);
    memcpy(g_in+32, h_ek,   32);
    auto g_out = sha3::sha3_512(g_in, 64);
    const uint8_t* r_prime = g_out.data() + 32;

    // K_bar = J(z ∥ c) = SHAKE256(z ∥ c, 32)  — implicit rejection key
    uint8_t j_in[32 + CT_BYTES];
    memcpy(j_in,    z,          32);
    memcpy(j_in+32, ct.data(), CT_BYTES);
    SharedSecret K_bar;
    sha3::shake256_into(j_in, sizeof(j_in), K_bar.data(), 32);

    // Re-encrypt with r' and compare ciphertexts
    Ciphertext ct_prime;
    pke_encrypt(ct_prime.data(), ek, m_prime, r_prime);

    // Constant-time select: return K' if ct==ct', else K_bar
    // NOTE: this implementation is for educational purposes;
    //       production use requires a genuine constant-time comparison.
    uint8_t diff = 0;
    for (size_t i = 0; i < CT_BYTES; ++i)
        diff |= ct.data()[i] ^ ct_prime.data()[i];

    // diff==0 → mask=0x00 → use K_prime; diff!=0 → mask=0xFF → use K_bar
    const uint8_t* K_prime = g_out.data();
    uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>(diff != 0));
    SharedSecret result;
    for (size_t i = 0; i < SS_BYTES; ++i)
        result[i] = (K_prime[i] & ~mask) | (K_bar[i] & mask);

    secure_zero(m_prime, sizeof(m_prime));
    secure_zero(g_in,    sizeof(g_in));
    secure_zero(g_out.data(), g_out.size());
    secure_zero(j_in,    sizeof(j_in));
    return result;
}

} // namespace mlkem
