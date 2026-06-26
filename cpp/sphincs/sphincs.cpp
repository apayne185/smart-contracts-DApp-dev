// SPHINCS+ / SLH-DSA-SHAKE-128s implementation (FIPS PUB 205)
//
// Hash functions (§10.2): all based on SHAKE256 with tweakable inputs built
// from PK.seed and an ADRS (address) struct for domain separation.
//
// Scheme layers (bottom to top):
//   WOTS+   one-time signature on a single n-byte value (§5)
//   XMSS    Merkle tree of WOTS+ public keys, signs one message (§6)
//   HT      d-layer stack of XMSS trees (hypertree) (§7)
//   FORS    few-time signature on the message digest indices (§8)
//   SLH-DSA keygen / sign / verify (§9–10)
#include "sphincs.h"
#include "../sha3/sha3.h"
#include <cassert>
#include <cstring>
#include <fstream>
#include <stdexcept>

namespace sphincs {

// Forward declaration of internal byte-array alias
using Bytes_N = std::array<uint8_t, N>;

// ── ADRS — tweakable address (FIPS 205 §4) ──────────────────────────────────
//
// A 32-byte structure encoding the position of a hash call within the scheme
// to prevent cross-context collisions.

enum class AdrsType : uint32_t {
    WOTS_HASH  = 0,
    WOTS_PK    = 1,
    HASH_TREE  = 2,
    FORS_TREE  = 3,
    FORS_ROOTS = 4,
    WOTS_PRF   = 5,
    FORS_PRF   = 6,
};

struct Adrs {
    uint8_t data[32] = {};

    void set_layer(uint32_t layer)       { store32(data,  layer); }
    void set_tree(uint64_t tree)         { store64(data + 8, tree); }
    void set_type(AdrsType t)            { store32(data + 16, static_cast<uint32_t>(t)); }
    void set_keypair(uint32_t kp)        { store32(data + 20, kp); }
    void set_chain(uint32_t c)           { store32(data + 24, c); }
    void set_hash(uint32_t h)            { store32(data + 28, h); }
    void set_tree_index(uint32_t idx)    { store32(data + 28, idx); }
    // For FORS: tree_height and tree_index share the same fields as chain/hash
    void set_tree_height(uint32_t h)     { store32(data + 24, h); }

private:
    static void store32(uint8_t* p, uint32_t v) {
        p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
    }
    static void store64(uint8_t* p, uint64_t v) {
        store32(p,   static_cast<uint32_t>(v >> 32));
        store32(p+4, static_cast<uint32_t>(v));
    }
};

// ── Tweakable hash functions (FIPS 205 §10.2, SHAKE variant) ────────────────
//
// All inner functions use shake256_into() with stack buffers to avoid heap
// allocation in the hot path (called millions of times during sign/verify).
//
// Maximum inner input: N + 32 + LEN*N = 16 + 32 + 35*16 = 608 bytes.
static constexpr size_t THASH_BUF_MAX = N + 32 + LEN * N;

static Bytes_N thash(const uint8_t* pk_seed, const Adrs& adrs,
                     const uint8_t* in, size_t in_len)
{
    uint8_t buf[THASH_BUF_MAX];
    memcpy(buf,          pk_seed, N);
    memcpy(buf + N,      adrs.data, 32);
    memcpy(buf + N + 32, in, in_len);
    Bytes_N out;
    sha3::shake256_into(buf, N + 32 + in_len, out.data(), N);
    return out;
}

// PRF: pseudorandom N-byte value for a given ADRS
static Bytes_N prf(const Bytes_N& pk_seed, const Bytes_N& sk_seed, const Adrs& adrs) {
    uint8_t buf[N + 32 + N];
    memcpy(buf,          pk_seed.data(), N);
    memcpy(buf + N,      adrs.data, 32);
    memcpy(buf + N + 32, sk_seed.data(), N);
    Bytes_N out;
    sha3::shake256_into(buf, sizeof(buf), out.data(), N);
    return out;
}

// PRF_msg: randomise the message (prevents chosen-message attacks)
static Bytes_N prf_msg(const Bytes_N& sk_prf, const Bytes_N& opt_rand,
                        const uint8_t* msg, size_t msg_len)
{
    std::vector<uint8_t> buf(N + N + msg_len);
    memcpy(buf.data(),       sk_prf.data(), N);
    memcpy(buf.data() + N,   opt_rand.data(), N);
    memcpy(buf.data() + 2*N, msg, msg_len);
    Bytes_N out;
    sha3::shake256_into(buf.data(), buf.size(), out.data(), N);
    return out;
}

// H_msg: hash to M-byte message digest (determines FORS indices + HT address)
static std::vector<uint8_t> h_msg(const Bytes_N& R, const Bytes_N& pk_seed,
                                   const Bytes_N& pk_root,
                                   const uint8_t* msg, size_t msg_len)
{
    std::vector<uint8_t> buf(3 * N + msg_len);
    memcpy(buf.data(),       R.data(), N);
    memcpy(buf.data() + N,   pk_seed.data(), N);
    memcpy(buf.data() + 2*N, pk_root.data(), N);
    memcpy(buf.data() + 3*N, msg, msg_len);
    std::vector<uint8_t> out(M);
    sha3::shake256_into(buf.data(), buf.size(), out.data(), M);
    return out;
}

// F (single-block tweakable hash) — WOTS+ chain step
static Bytes_N F(const Bytes_N& pk_seed, const Adrs& adrs, const Bytes_N& in) {
    return thash(pk_seed.data(), adrs, in.data(), N);
}

// hash2: two-block tweakable hash — Merkle tree node
static Bytes_N hash2(const Bytes_N& pk_seed, const Adrs& adrs,
                      const Bytes_N& left, const Bytes_N& right)
{
    uint8_t buf[2*N];
    memcpy(buf,   left.data(),  N);
    memcpy(buf+N, right.data(), N);
    return thash(pk_seed.data(), adrs, buf, 2*N);
}

// T_l (l-block tweakable hash) — compresses l N-byte inputs
static Bytes_N T_l(const Bytes_N& pk_seed, const Adrs& adrs,
                    const uint8_t* in, size_t l)
{
    return thash(pk_seed.data(), adrs, in, l * N);
}

// ── Utility ──────────────────────────────────────────────────────────────────

// Convert a byte string to base-W digits (FIPS 205 §2.5)
static std::vector<uint8_t> base_w(const uint8_t* in, size_t out_len) {
    std::vector<uint8_t> out(out_len);
    size_t in_idx = 0, bits = 0;
    uint32_t total = 0;
    for (size_t i = 0; i < out_len; ++i) {
        if (bits == 0) { total = in[in_idx++]; bits = 8; }
        bits -= LOG_W;
        out[i] = (total >> bits) & (W - 1);
    }
    return out;
}

// Compute WOTS+ checksum over base-W digits
static std::vector<uint8_t> wots_checksum(const std::vector<uint8_t>& msg_w) {
    uint32_t csum = 0;
    for (auto b : msg_w) csum += W - 1 - b;
    // encode csum into ceil(log2(LEN1*(W-1)+1)/LOG_W) = LEN2 = 3 digits
    csum <<= (8 - ((LEN2 * LOG_W) % 8)) % 8;
    uint8_t bytes[2] = { static_cast<uint8_t>(csum >> 8),
                         static_cast<uint8_t>(csum) };
    return base_w(bytes, LEN2);
}

static uint64_t bytes_to_u64(const uint8_t* p, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) v = (v << 8) | p[i];
    return v;
}

// ── WOTS+ (§5) ───────────────────────────────────────────────────────────────

// Compute chain: apply F i times starting from X with chain index s
static Bytes_N chain(Bytes_N X, size_t start, size_t steps,
                     const Bytes_N& pk_seed, Adrs adrs)
{
    for (size_t i = start; i < start + steps && i < W; ++i) {
        adrs.set_hash(static_cast<uint32_t>(i));
        X = F(pk_seed, adrs, X);
    }
    return X;
}

// Generate WOTS+ key pair: returns (sk_nodes[LEN], pk)
static std::pair<std::vector<Bytes_N>, Bytes_N>
wots_keygen(const Bytes_N& sk_seed, const Bytes_N& pk_seed,
            uint32_t layer, uint64_t tree_idx, uint32_t keypair_idx)
{
    Adrs adrs{};
    adrs.set_layer(layer);
    adrs.set_tree(tree_idx);
    adrs.set_keypair(keypair_idx);

    // Generate secret key elements via PRF
    std::vector<Bytes_N> sk(LEN);
    adrs.set_type(AdrsType::WOTS_PRF);
    for (size_t i = 0; i < LEN; ++i) {
        adrs.set_chain(static_cast<uint32_t>(i));
        sk[i] = prf(pk_seed, sk_seed, adrs);
    }

    // Compute public key elements by chaining W-1 times
    adrs.set_type(AdrsType::WOTS_HASH);
    std::vector<uint8_t> pk_elements(LEN * N);
    for (size_t i = 0; i < LEN; ++i) {
        adrs.set_chain(static_cast<uint32_t>(i));
        Bytes_N pk_i = chain(sk[i], 0, W - 1, pk_seed, adrs);
        memcpy(pk_elements.data() + i * N, pk_i.data(), N);
    }

    // Compress public key
    adrs.set_type(AdrsType::WOTS_PK);
    Bytes_N pk = T_l(pk_seed, adrs, pk_elements.data(), LEN);
    return { std::move(sk), pk };
}

// WOTS+ sign: returns a LEN*N-byte signature
static std::vector<uint8_t>
wots_sign(const Bytes_N& msg, const Bytes_N& sk_seed, const Bytes_N& pk_seed,
          uint32_t layer, uint64_t tree_idx, uint32_t keypair_idx)
{
    auto msg_w  = base_w(msg.data(), LEN1);
    auto csum_w = wots_checksum(msg_w);
    msg_w.insert(msg_w.end(), csum_w.begin(), csum_w.end());
    assert(msg_w.size() == LEN);

    Adrs adrs{};
    adrs.set_layer(layer);
    adrs.set_tree(tree_idx);
    adrs.set_keypair(keypair_idx);

    std::vector<uint8_t> sig(LEN * N);
    adrs.set_type(AdrsType::WOTS_PRF);
    for (size_t i = 0; i < LEN; ++i) {
        adrs.set_chain(static_cast<uint32_t>(i));
        Bytes_N sk_i = prf(pk_seed, sk_seed, adrs);
        adrs.set_type(AdrsType::WOTS_HASH);
        Bytes_N sig_i = chain(sk_i, 0, msg_w[i], pk_seed, adrs);
        memcpy(sig.data() + i * N, sig_i.data(), N);
        adrs.set_type(AdrsType::WOTS_PRF);
    }
    return sig;
}

// WOTS+ verify: recover public key from signature
static Bytes_N
wots_pk_from_sig(const std::vector<uint8_t>& sig, const Bytes_N& msg,
                 const Bytes_N& pk_seed,
                 uint32_t layer, uint64_t tree_idx, uint32_t keypair_idx)
{
    auto msg_w  = base_w(msg.data(), LEN1);
    auto csum_w = wots_checksum(msg_w);
    msg_w.insert(msg_w.end(), csum_w.begin(), csum_w.end());

    Adrs adrs{};
    adrs.set_layer(layer);
    adrs.set_tree(tree_idx);
    adrs.set_keypair(keypair_idx);
    adrs.set_type(AdrsType::WOTS_HASH);

    std::vector<uint8_t> pk_elements(LEN * N);
    for (size_t i = 0; i < LEN; ++i) {
        Bytes_N sig_i;
        memcpy(sig_i.data(), sig.data() + i * N, N);
        adrs.set_chain(static_cast<uint32_t>(i));
        Bytes_N pk_i = chain(sig_i, msg_w[i], W - 1 - msg_w[i], pk_seed, adrs);
        memcpy(pk_elements.data() + i * N, pk_i.data(), N);
    }

    adrs.set_type(AdrsType::WOTS_PK);
    return T_l(pk_seed, adrs, pk_elements.data(), LEN);
}

// ── XMSS tree (§6) ───────────────────────────────────────────────────────────

// Build an HP-height Merkle tree over 2^HP WOTS+ public keys.
// Returns root and the authentication path for leaf_idx.
struct XmssTree {
    Bytes_N root;
    std::vector<Bytes_N> auth;  // HP nodes (sibling at each level)
};

static XmssTree xmss_tree(const Bytes_N& sk_seed, const Bytes_N& pk_seed,
                            uint32_t layer, uint64_t tree_idx,
                            uint32_t leaf_idx)
{
    size_t num_leaves = size_t(1) << HP;
    std::vector<Bytes_N> nodes(2 * num_leaves);

    // Compute all leaf WOTS+ public keys
    for (size_t i = 0; i < num_leaves; ++i) {
        auto [_, pk] = wots_keygen(sk_seed, pk_seed, layer, tree_idx,
                                   static_cast<uint32_t>(i));
        nodes[num_leaves + i] = pk;
    }

    // Build tree bottom-up
    Adrs adrs{};
    adrs.set_layer(layer);
    adrs.set_tree(tree_idx);
    adrs.set_type(AdrsType::HASH_TREE);

    for (size_t h = 0; h < HP; ++h) {
        size_t level_start = num_leaves >> (h + 1);
        for (size_t i = 0; i < (num_leaves >> (h + 1)); ++i) {
            size_t left  = (level_start << 1) + 2 * i;
            size_t right = left + 1;
            adrs.set_tree_height(static_cast<uint32_t>(h));
            adrs.set_tree_index(static_cast<uint32_t>(i));  // i = within-level index
            nodes[level_start + i] = hash2(pk_seed, adrs, nodes[left], nodes[right]);
        }
    }

    XmssTree result;
    result.root = nodes[1];

    // Collect authentication path (sibling at each level)
    result.auth.resize(HP);
    size_t idx = leaf_idx + num_leaves;
    for (size_t h = 0; h < HP; ++h) {
        result.auth[h] = nodes[idx ^ 1];
        idx >>= 1;
    }
    return result;
}

// Compute XMSS root from a leaf value and authentication path
static Bytes_N xmss_root_from_sig(Bytes_N leaf, uint32_t leaf_idx,
                                    const std::vector<Bytes_N>& auth,
                                    const Bytes_N& pk_seed,
                                    uint32_t layer, uint64_t tree_idx)
{
    Adrs adrs{};
    adrs.set_layer(layer);
    adrs.set_tree(tree_idx);
    adrs.set_type(AdrsType::HASH_TREE);

    for (size_t h = 0; h < HP; ++h) {
        uint32_t idx_h = (leaf_idx >> h) & 1;
        uint32_t node_idx = (leaf_idx >> (h + 1));
        adrs.set_tree_height(static_cast<uint32_t>(h));
        adrs.set_tree_index(node_idx);
        if (idx_h == 0)
            leaf = hash2(pk_seed, adrs, leaf, auth[h]);
        else
            leaf = hash2(pk_seed, adrs, auth[h], leaf);
    }
    return leaf;
}

// ── FORS (§8) ────────────────────────────────────────────────────────────────
//
// FORS signs an a*k-bit string by selecting one leaf from each of k binary
// trees of height a, then hashing all k roots together.

struct ForsSig {
    std::vector<Bytes_N> sk_values;   // K secret leaf values
    std::vector<std::vector<Bytes_N>> auth; // K auth paths, each A nodes
};

// Hash one FORS leaf sk → H( pk_seed, ADRS, sk )
static Bytes_N fors_leaf(const Bytes_N& sk_seed, const Bytes_N& pk_seed,
                          uint32_t keypair_idx, uint32_t tree, uint32_t leaf,
                          const Adrs& base_adrs)
{
    Adrs adrs = base_adrs;
    adrs.set_type(AdrsType::FORS_PRF);
    adrs.set_keypair(keypair_idx);
    adrs.set_tree_height(0);
    adrs.set_tree_index(tree * (1u << A) + leaf);
    Bytes_N sk = prf(pk_seed, sk_seed, adrs);

    adrs.set_type(AdrsType::FORS_TREE);
    adrs.set_tree_height(0);
    adrs.set_tree_index(tree * (1u << A) + leaf);
    return F(pk_seed, adrs, sk);
}

// Build the full k FORS trees, return the compressed public key and the
// signature (k chosen leaves + their auth paths) for the given indices.
static std::pair<Bytes_N, ForsSig>
fors_sign_and_pk(const uint8_t* indices, // K indices, each A bits
                 const Bytes_N& sk_seed, const Bytes_N& pk_seed,
                 uint32_t keypair_idx,
                 const Adrs& base_adrs)
{
    size_t leaves = size_t(1) << A;
    ForsSig fsig;
    fsig.sk_values.resize(K);
    fsig.auth.resize(K, std::vector<Bytes_N>(A));

    std::vector<Bytes_N> roots(K);

    for (size_t t = 0; t < K; ++t) {
        uint32_t idx = indices[t];  // A-bit index

        // Secret leaf
        Adrs adrs = base_adrs;
        adrs.set_type(AdrsType::FORS_PRF);
        adrs.set_keypair(keypair_idx);
        adrs.set_tree_index(static_cast<uint32_t>(t * leaves + idx));
        fsig.sk_values[t] = prf(pk_seed, sk_seed, adrs);

        // Build tree and collect auth path
        std::vector<Bytes_N> tree_nodes(2 * leaves);
        for (size_t l = 0; l < leaves; ++l)
            tree_nodes[leaves + l] = fors_leaf(sk_seed, pk_seed, keypair_idx,
                                                static_cast<uint32_t>(t),
                                                static_cast<uint32_t>(l),
                                                base_adrs);

        for (size_t h = 0; h < A; ++h) {
            size_t level_start = leaves >> (h + 1);
            for (size_t i = 0; i < level_start; ++i) {
                size_t left  = (level_start << 1) + 2 * i;
                size_t right = left + 1;
                Adrs ha = base_adrs;
                ha.set_type(AdrsType::FORS_TREE);
                ha.set_keypair(keypair_idx);
                ha.set_tree_height(static_cast<uint32_t>(h + 1));
                ha.set_tree_index(static_cast<uint32_t>(t * (leaves >> (h+1)) + i));
                tree_nodes[level_start + i] = hash2(pk_seed, ha,
                                                 tree_nodes[left],
                                                 tree_nodes[right]);
            }
        }

        roots[t] = tree_nodes[1];

        // Auth path
        size_t node_idx = idx + leaves;
        for (size_t h = 0; h < A; ++h) {
            fsig.auth[t][h] = tree_nodes[node_idx ^ 1];
            node_idx >>= 1;
        }
    }

    // Compress k roots → FORS public key
    std::vector<uint8_t> roots_buf(K * N);
    for (size_t t = 0; t < K; ++t)
        memcpy(roots_buf.data() + t * N, roots[t].data(), N);
    Adrs fors_pk_adrs = base_adrs;
    fors_pk_adrs.set_type(AdrsType::FORS_ROOTS);
    fors_pk_adrs.set_keypair(keypair_idx);
    Bytes_N fors_pk = T_l(pk_seed, fors_pk_adrs, roots_buf.data(), K);

    return { fors_pk, std::move(fsig) };
}

// Recover FORS public key from signature
static Bytes_N fors_pk_from_sig(const ForsSig& fsig,
                                  const uint8_t* indices,
                                  const Bytes_N& pk_seed,
                                  uint32_t keypair_idx,
                                  const Adrs& base_adrs)
{
    size_t leaves = size_t(1) << A;
    std::vector<Bytes_N> roots(K);

    for (size_t t = 0; t < K; ++t) {
        uint32_t idx = indices[t];

        // Recover leaf from secret value
        Adrs adrs = base_adrs;
        adrs.set_type(AdrsType::FORS_TREE);
        adrs.set_keypair(keypair_idx);
        adrs.set_tree_height(0);
        adrs.set_tree_index(static_cast<uint32_t>(t * leaves + idx));
        Bytes_N leaf = F(pk_seed, adrs, fsig.sk_values[t]);

        // Walk up with auth path
        size_t node_idx = idx;
        Bytes_N node = leaf;
        for (size_t h = 0; h < A; ++h) {
            Adrs ha = base_adrs;
            ha.set_type(AdrsType::FORS_TREE);
            ha.set_keypair(keypair_idx);
            ha.set_tree_height(static_cast<uint32_t>(h + 1));
            ha.set_tree_index(static_cast<uint32_t>(t * (leaves >> h) / 2 + node_idx / 2));
            if ((node_idx & 1) == 0)
                node = hash2(pk_seed, ha, node, fsig.auth[t][h]);
            else
                node = hash2(pk_seed, ha, fsig.auth[t][h], node);
            node_idx >>= 1;
        }
        roots[t] = node;
    }

    std::vector<uint8_t> roots_buf(K * N);
    for (size_t t = 0; t < K; ++t)
        memcpy(roots_buf.data() + t * N, roots[t].data(), N);
    Adrs fors_pk_adrs = base_adrs;
    fors_pk_adrs.set_type(AdrsType::FORS_ROOTS);
    fors_pk_adrs.set_keypair(keypair_idx);
    return T_l(pk_seed, fors_pk_adrs, roots_buf.data(), K);
}

// ── Message digest parsing (§9.2) ────────────────────────────────────────────
//
// The M-byte digest md = H_msg(R || PK.seed || PK.root || msg) encodes:
//   ka bits  → k A-bit FORS tree indices
//   h-d bits → layer-0 tree address within the hypertree
//   d*hp bits → leaf indices at each HT layer   (just needs lowest-layer leaf)
// We extract these as:
//   fors_indices[K]: each A bits (ka total from first ceil(ka/8) bytes)
//   tree_idx       : from next ceil((h-d)/8) bytes
//   leaf_idx       : from next ceil(hp/8) bytes = 1 byte (HP=9 fits in 12 bits)

struct DigestParts {
    uint8_t  fors_indices[K]; // each 0..2^A-1
    uint64_t tree_idx;        // which HT tree at layer 0
    uint32_t leaf_idx;        // leaf within that tree
};

static DigestParts parse_digest(const std::vector<uint8_t>& md) {
    // ka = K * A = 14 * 12 = 168 bits = 21 bytes
    // (h - d) = 63 - 7 = 56 bits = 7 bytes  → tree_idx
    // hp = 9 bits = 2 bytes                   → leaf_idx (lower 9 bits)
    assert(md.size() >= M);

    DigestParts dp{};

    // Extract K*A bits for FORS indices
    uint32_t bit_buf = 0;
    int bits_in_buf = 0;
    size_t byte_pos = 0;
    for (size_t i = 0; i < K; ++i) {
        while (bits_in_buf < static_cast<int>(A)) {
            bit_buf = (bit_buf << 8) | md[byte_pos++];
            bits_in_buf += 8;
        }
        bits_in_buf -= A;
        dp.fors_indices[i] = (bit_buf >> bits_in_buf) & ((1u << A) - 1);
    }

    // Next 7 bytes → tree_idx.  The digest has h-d=56 bits, but the hypertree
    // has only 2^(HP*(D-1)) = 2^54 bottom-layer trees: after D-1 shifts of HP
    // bits the top-layer tree index uses bits 54-55, which must be 0 so that
    // keygen (which always builds tree 0 at layer D-1) matches signing.
    // Mask to HP*(D-1) = 54 bits to enforce this invariant.
    dp.tree_idx = bytes_to_u64(md.data() + 21, 7);
    dp.tree_idx &= (uint64_t(1) << (HP * (D - 1))) - 1;

    // Next 2 bytes → leaf_idx (lower HP=9 bits)
    dp.leaf_idx = ((uint32_t(md[28]) << 8) | md[29]) & ((1u << HP) - 1);

    return dp;
}

// ── Random bytes ──────────────────────────────────────────────────────────────

static void random_bytes(uint8_t* out, size_t n) {
    std::ifstream rng("/dev/urandom", std::ios::binary);
    if (!rng) throw std::runtime_error("Cannot open /dev/urandom");
    rng.read(reinterpret_cast<char*>(out), static_cast<std::streamsize>(n));
}

// ── Public API ────────────────────────────────────────────────────────────────

SphincsKey keygen(const std::array<uint8_t, 3 * N>& seed) {
    SphincsKey kp{};
    memcpy(kp.sk.sk_seed.data(), seed.data(),          N);
    memcpy(kp.sk.sk_prf.data(),  seed.data() + N,      N);
    memcpy(kp.sk.pk_seed.data(), seed.data() + 2 * N,  N);
    kp.pk.pk_seed = kp.sk.pk_seed;

    // Root = XMSS root at the top layer (layer D-1, tree 0, leaf 0 not needed)
    // We need the root of the topmost XMSS tree.
    // Build the topmost tree (layer D-1, tree_idx 0, sign leaf 0).
    auto top = xmss_tree(kp.sk.sk_seed, kp.sk.pk_seed,
                          static_cast<uint32_t>(D - 1), 0, 0);
    kp.sk.pk_root = kp.pk.pk_root = top.root;
    return kp;
}

Signature sign(const uint8_t* msg, size_t msg_len,
               const SecretKey& sk, const uint8_t* opt_rand_in)
{
    Bytes_N opt_rand{};
    if (opt_rand_in) {
        memcpy(opt_rand.data(), opt_rand_in, N);
    } else {
        random_bytes(opt_rand.data(), N);
    }

    // 1. Randomise the message
    Bytes_N R = prf_msg(sk.sk_prf, opt_rand, msg, msg_len);

    // 2. Hash to message digest
    auto md = h_msg(R, sk.pk_seed, sk.pk_root, msg, msg_len);
    auto dp = parse_digest(md);

    // 3. FORS signature
    Adrs fors_adrs{};
    fors_adrs.set_layer(0);
    fors_adrs.set_tree(dp.tree_idx);
    fors_adrs.set_keypair(dp.leaf_idx);

    auto [fors_pk, fsig] = fors_sign_and_pk(dp.fors_indices,
                                              sk.sk_seed, sk.pk_seed,
                                              dp.leaf_idx, fors_adrs);

    // 4. HT signature (signs fors_pk through D XMSS layers)
    // At each layer the leaf index is the low HP bits of the layer's tree index
    uint64_t tree_idx = dp.tree_idx;
    uint32_t leaf_idx = dp.leaf_idx;

    Bytes_N msg_to_sign = fors_pk;
    std::vector<uint8_t> ht_sig;
    ht_sig.reserve(HT_SIG_BYTES);

    for (size_t layer = 0; layer < D; ++layer) {
        // WOTS+ sign msg_to_sign
        auto wots_sig = wots_sign(msg_to_sign, sk.sk_seed, sk.pk_seed,
                                   static_cast<uint32_t>(layer),
                                   tree_idx, leaf_idx);
        ht_sig.insert(ht_sig.end(), wots_sig.begin(), wots_sig.end());

        // Auth path for this XMSS layer
        auto xt = xmss_tree(sk.sk_seed, sk.pk_seed,
                             static_cast<uint32_t>(layer),
                             tree_idx, leaf_idx);
        for (auto& node : xt.auth)
            ht_sig.insert(ht_sig.end(), node.begin(), node.end());

        // Next layer: sign the root of this layer's tree
        msg_to_sign = xt.root;
        // Move up: leaf_idx = which sub-tree we were in (low HP bits of tree_idx)
        leaf_idx = static_cast<uint32_t>(tree_idx & ((1u << HP) - 1));
        tree_idx >>= HP;
    }

    // 5. Serialise: R || FORS sig || HT sig
    Signature sig;
    sig.reserve(SIG_BYTES);
    sig.insert(sig.end(), R.begin(), R.end());

    // FORS sig: K * (1 sk_value + A auth nodes)
    for (size_t t = 0; t < K; ++t) {
        sig.insert(sig.end(), fsig.sk_values[t].begin(), fsig.sk_values[t].end());
        for (size_t h = 0; h < A; ++h)
            sig.insert(sig.end(), fsig.auth[t][h].begin(), fsig.auth[t][h].end());
    }

    sig.insert(sig.end(), ht_sig.begin(), ht_sig.end());
    return sig;
}

bool verify(const uint8_t* msg, size_t msg_len,
            const Signature& sig, const PublicKey& pk)
{
    if (sig.size() != SIG_BYTES) return false;

    const uint8_t* ptr = sig.data();

    // 1. Unpack R
    Bytes_N R; memcpy(R.data(), ptr, N); ptr += N;

    // 2. Recompute digest
    auto md = h_msg(R, pk.pk_seed, pk.pk_root, msg, msg_len);
    auto dp = parse_digest(md);

    // 3. Unpack FORS sig
    ForsSig fsig;
    fsig.sk_values.resize(K);
    fsig.auth.resize(K, std::vector<Bytes_N>(A));
    for (size_t t = 0; t < K; ++t) {
        memcpy(fsig.sk_values[t].data(), ptr, N); ptr += N;
        for (size_t h = 0; h < A; ++h) {
            memcpy(fsig.auth[t][h].data(), ptr, N); ptr += N;
        }
    }

    // 4. Recover FORS public key
    Adrs fors_adrs{};
    fors_adrs.set_layer(0);
    fors_adrs.set_tree(dp.tree_idx);
    fors_adrs.set_keypair(dp.leaf_idx);

    Bytes_N fors_pk = fors_pk_from_sig(fsig, dp.fors_indices,
                                        pk.pk_seed, dp.leaf_idx, fors_adrs);

    // 5. Walk up HT
    uint64_t tree_idx = dp.tree_idx;
    uint32_t leaf_idx = dp.leaf_idx;
    Bytes_N node = fors_pk;

    for (size_t layer = 0; layer < D; ++layer) {
        // Unpack WOTS+ sig (LEN * N bytes)
        std::vector<uint8_t> wots_sig(LEN * N);
        memcpy(wots_sig.data(), ptr, LEN * N); ptr += LEN * N;

        // Recover WOTS+ public key from sig
        Bytes_N wots_pk = wots_pk_from_sig(wots_sig, node, pk.pk_seed,
                                            static_cast<uint32_t>(layer),
                                            tree_idx, leaf_idx);

        // Unpack auth path (HP * N bytes)
        std::vector<Bytes_N> auth(HP);
        for (size_t h = 0; h < HP; ++h) {
            memcpy(auth[h].data(), ptr, N); ptr += N;
        }

        // Walk up XMSS tree
        node = xmss_root_from_sig(wots_pk, leaf_idx, auth, pk.pk_seed,
                                   static_cast<uint32_t>(layer), tree_idx);

        // Advance to next layer
        leaf_idx = static_cast<uint32_t>(tree_idx & ((1u << HP) - 1));
        tree_idx >>= HP;
    }

    // node must equal pk_root
    return node == pk.pk_root;
}

Signature sign(const std::vector<uint8_t>& msg, const SecretKey& sk,
               const uint8_t* opt_rand)
{
    return sign(msg.data(), msg.size(), sk, opt_rand);
}

bool verify(const std::vector<uint8_t>& msg, const Signature& sig,
            const PublicKey& pk)
{
    return verify(msg.data(), msg.size(), sig, pk);
}

} // namespace sphincs
