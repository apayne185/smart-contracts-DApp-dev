// Raw Bitcoin P2PKH Transaction Builder (Testnet)
//
// Builds, signs, and serialises a Pay-to-Public-Key-Hash (P2PKH) transaction
// from scratch without any Bitcoin library, following the Bitcoin protocol spec:
//
//   https://en.bitcoin.it/wiki/Protocol_documentation#tx
//   https://en.bitcoin.it/wiki/OP_CHECKSIG (SIGHASH_ALL)
//
// What this demonstrates:
//   • varint / CompactSize encoding
//   • Script opcodes: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
//   • Base58Check encode/decode with full checksum verification
//   • SIGHASH_ALL pre-image construction (the exact bytes the ECDSA key signs)
//   • Double-SHA256 (hash256) used for sighash and TXID derivation
//   • DER-encoded ECDSA signature assembly (structure, not live signing)
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "../sha256/sha256.h"

// ── Utility: byte buffer ──────────────────────────────────────────────────────

using Bytes = std::vector<uint8_t>;

static std::string to_hex(const Bytes& b) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : b) ss << std::setw(2) << int(byte);
    return ss.str();
}

static Bytes from_hex(const std::string& hex) {
    if (hex.size() % 2 != 0) throw std::invalid_argument("odd-length hex");
    Bytes out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i)
        out[i] = uint8_t(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
    return out;
}

// ── Hash256 (double SHA-256) ──────────────────────────────────────────────────

static sha256::Digest hash256(const Bytes& data) {
    auto first  = sha256::hash(data.data(), data.size());
    auto second = sha256::hash(first.data(), first.size());
    return second;
}

// ── Base58Check ───────────────────────────────────────────────────────────────

static constexpr char BASE58_ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Encode bytes as Base58Check (prepend version, append 4-byte checksum)
static std::string base58check_encode(uint8_t version, const Bytes& payload) {
    Bytes full;
    full.push_back(version);
    full.insert(full.end(), payload.begin(), payload.end());

    // Checksum = first 4 bytes of hash256(full)
    auto h = hash256(full);
    for (int i = 0; i < 4; ++i) full.push_back(h[i]);

    // Count leading zero bytes → leading '1's in the output
    size_t leading_zeros = 0;
    for (uint8_t b : full) { if (b == 0) ++leading_zeros; else break; }

    // Convert big-endian byte array to base-58 digits
    // We treat `full` as a big-endian big integer and repeatedly divide by 58.
    Bytes tmp(full);
    std::string result;
    while (!tmp.empty() && !(tmp.size() == 1 && tmp[0] == 0)) {
        int rem = 0;
        for (uint8_t& byte : tmp) {
            int cur = rem * 256 + byte;
            byte    = uint8_t(cur / 58);
            rem     = cur % 58;
        }
        result.push_back(BASE58_ALPHABET[rem]);
        while (!tmp.empty() && tmp.front() == 0) tmp.erase(tmp.begin());
    }
    for (size_t i = 0; i < leading_zeros; ++i) result.push_back('1');
    std::reverse(result.begin(), result.end());
    return result;
}

// Decode a Base58Check address and return the 20-byte payload (sans version byte)
static Bytes base58check_decode(const std::string& addr) {
    // Convert base-58 string → big-endian byte array using schoolbook division
    Bytes bytes;
    for (char c : addr) {
        const char* p = std::strchr(BASE58_ALPHABET, c);
        if (!p) throw std::invalid_argument(std::string("invalid base58 char: ") + c);
        int carry = int(p - BASE58_ALPHABET);
        for (int i = int(bytes.size()) - 1; i >= 0; --i) {
            carry += 58 * bytes[i];
            bytes[i] = uint8_t(carry & 0xFF);
            carry >>= 8;
        }
        while (carry > 0) {
            bytes.insert(bytes.begin(), uint8_t(carry & 0xFF));
            carry >>= 8;
        }
    }

    // Prepend leading zero bytes for each leading '1' in the address
    size_t leading_ones = 0;
    for (char c : addr) { if (c == '1') ++leading_ones; else break; }
    bytes.insert(bytes.begin(), leading_ones, 0x00);

    // bytes = [version(1)] + [hash(20)] + [checksum(4)]
    if (bytes.size() < 5) throw std::invalid_argument("decoded payload too short");

    Bytes payload(bytes.begin(),     bytes.end() - 4);
    Bytes checksum(bytes.end() - 4, bytes.end());

    auto h = hash256(payload);
    for (int i = 0; i < 4; ++i)
        if (h[i] != checksum[i])
            throw std::invalid_argument("base58check checksum mismatch");

    // Skip version byte; return the 20-byte pubkey hash
    return Bytes(payload.begin() + 1, payload.end());
}

// ── Bitcoin varint (CompactSize) encoding ─────────────────────────────────────

static void push_varint(Bytes& out, uint64_t n) {
    if (n < 0xFD) {
        out.push_back(uint8_t(n));
    } else if (n <= 0xFFFF) {
        out.push_back(0xFD);
        out.push_back(uint8_t(n));
        out.push_back(uint8_t(n >> 8));
    } else if (n <= 0xFFFFFFFF) {
        out.push_back(0xFE);
        for (int i = 0; i < 4; ++i) out.push_back(uint8_t(n >> (i * 8)));
    } else {
        out.push_back(0xFF);
        for (int i = 0; i < 8; ++i) out.push_back(uint8_t(n >> (i * 8)));
    }
}

static void push_le32(Bytes& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(uint8_t(v >> (i * 8)));
}

static void push_le64(Bytes& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(uint8_t(v >> (i * 8)));
}

static void push_bytes(Bytes& out, const Bytes& b) {
    out.insert(out.end(), b.begin(), b.end());
}

// ── P2PKH scriptPubKey ────────────────────────────────────────────────────────
// OP_DUP(0x76) OP_HASH160(0xa9) PUSH20(0x14) <hash160> OP_EQUALVERIFY(0x88) OP_CHECKSIG(0xac)

static Bytes make_p2pkh_scriptpubkey(const Bytes& pubkey_hash) {
    assert(pubkey_hash.size() == 20);
    Bytes s = {0x76, 0xa9, 0x14};
    push_bytes(s, pubkey_hash);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

static Bytes make_p2pkh_scriptpubkey(const std::string& address) {
    return make_p2pkh_scriptpubkey(base58check_decode(address));
}

// ── SIGHASH_ALL pre-image ─────────────────────────────────────────────────────
// The byte sequence that gets hash256'd to produce the 32-byte signing digest.
// Reference: https://en.bitcoin.it/wiki/OP_CHECKSIG#Procedure_for_Hashtype_SIGHASH_ALL

static Bytes build_sighash_preimage(
    const std::string& prev_txid_hex,
    uint32_t           prev_vout,
    const std::string& src_address,
    uint64_t           amount_sats,
    const std::string& dest_address)
{
    Bytes p;
    push_le32(p, 1); // version

    push_varint(p, 1); // one input
    Bytes txid = from_hex(prev_txid_hex);
    std::reverse(txid.begin(), txid.end()); // display order → internal byte order
    push_bytes(p, txid);
    push_le32(p, prev_vout);
    Bytes prev_script = make_p2pkh_scriptpubkey(src_address);
    push_varint(p, prev_script.size());
    push_bytes(p, prev_script);
    push_le32(p, 0xFFFFFFFF); // sequence

    push_varint(p, 1); // one output
    push_le64(p, amount_sats);
    Bytes dest_script = make_p2pkh_scriptpubkey(dest_address);
    push_varint(p, dest_script.size());
    push_bytes(p, dest_script);

    push_le32(p, 0); // locktime
    push_le32(p, 1); // SIGHASH_ALL (appended only in the preimage, not the final tx)
    return p;
}

// ── Final serialised transaction ──────────────────────────────────────────────

static Bytes build_signed_tx(
    const std::string& prev_txid_hex,
    uint32_t           prev_vout,
    uint64_t           amount_sats,
    const std::string& dest_address,
    const Bytes&       der_sig,
    const Bytes&       pubkey_compressed)
{
    Bytes script_sig;
    push_varint(script_sig, der_sig.size());
    push_bytes(script_sig, der_sig);
    push_varint(script_sig, pubkey_compressed.size());
    push_bytes(script_sig, pubkey_compressed);

    Bytes dest_script = make_p2pkh_scriptpubkey(dest_address);

    Bytes tx;
    push_le32(tx, 1); // version
    push_varint(tx, 1); // input count

    Bytes txid = from_hex(prev_txid_hex);
    std::reverse(txid.begin(), txid.end());
    push_bytes(tx, txid);
    push_le32(tx, prev_vout);
    push_varint(tx, script_sig.size());
    push_bytes(tx, script_sig);
    push_le32(tx, 0xFFFFFFFF); // sequence

    push_varint(tx, 1); // output count
    push_le64(tx, amount_sats);
    push_varint(tx, dest_script.size());
    push_bytes(tx, dest_script);

    push_le32(tx, 0); // locktime
    return tx;
}

// ── Demo ──────────────────────────────────────────────────────────────────────

int main() {
    std::cout << "Bitcoin P2PKH Raw Transaction Builder\n";
    std::cout << "======================================\n\n";

    // Generate valid testnet P2PKH addresses from raw pubkey hashes.
    // In a real wallet these hashes come from HASH160(compressed_pubkey).
    // Version 0x6F = testnet P2PKH.
    Bytes src_hash(20, 0xAB); // placeholder: "wallet A" pubkey hash
    Bytes dst_hash(20, 0xCD); // placeholder: "wallet B" pubkey hash
    std::string src_addr = base58check_encode(0x6F, src_hash);
    std::string dst_addr = base58check_encode(0x6F, dst_hash);

    std::cout << "Source address  (wallet A): " << src_addr << "\n";
    std::cout << "Dest   address  (wallet B): " << dst_addr << "\n\n";

    // Round-trip verification
    assert(base58check_decode(src_addr) == src_hash);
    assert(base58check_decode(dst_addr) == dst_hash);
    std::cout << "[OK] Base58Check encode/decode round-trip verified\n\n";

    const std::string prev_txid = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
                                  "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    const uint32_t prev_vout  = 0;
    const uint64_t amount     = 90000; // satoshis after 1 000 sat fee

    // ── Step 1: SIGHASH_ALL pre-image ─────────────────────────────────────────
    Bytes preimage = build_sighash_preimage(prev_txid, prev_vout, src_addr, amount, dst_addr);
    auto  sighash  = hash256(preimage);

    std::cout << "SIGHASH_ALL preimage (" << preimage.size() << " bytes):\n  "
              << to_hex(preimage) << "\n\n";
    std::cout << "Signing digest (hash256 of preimage):\n  "
              << sha256::to_hex(sighash) << "\n\n";

    // ── Step 2: ECDSA sign (stub) ─────────────────────────────────────────────
    // Production path: pass `sighash` to libsecp256k1:
    //   secp256k1_ecdsa_sign(ctx, &sig, sighash.data(), privkey, nullptr, nullptr)
    //   secp256k1_ecdsa_signature_serialize_der(ctx, der_buf, &der_len, &sig)
    std::cout << "[STUB] secp256k1 ECDSA signing would happen here.\n";
    std::cout << "       The 32-byte digest above is the exact input to sign.\n\n";

    // Minimal valid-structured DER signature placeholder (r=32 bytes, s=32 bytes)
    Bytes fake_sig = {
        0x30, 0x44,
        0x02, 0x20,
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x11,0x22,0x33,0x44,
        0x55,0x66,0x77,0x88,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x02, 0x20,
        0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0xaa,0xbb,0xcc,0xdd,
        0xee,0xff,0x00,0x11,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,
        0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,
        0x01 // SIGHASH_ALL type byte
    };
    Bytes fake_pubkey(33, 0x02); // placeholder compressed pubkey (33 bytes)

    // ── Step 3: assemble and serialise the signed transaction ─────────────────
    Bytes raw_tx = build_signed_tx(prev_txid, prev_vout, amount, dst_addr,
                                   fake_sig, fake_pubkey);

    std::cout << "Serialised raw transaction (" << raw_tx.size() << " bytes):\n  "
              << to_hex(raw_tx) << "\n\n";

    // TXID = hash256(raw_tx), reversed to display byte order
    auto txid_bytes = hash256(raw_tx);
    Bytes txid(txid_bytes.begin(), txid_bytes.end());
    std::reverse(txid.begin(), txid.end());
    std::cout << "TXID (display order, after real signing):\n  " << to_hex(txid) << "\n\n";

    std::cout << "Transaction summary:\n"
              << "  Version   : 1\n"
              << "  Inputs    : 1  (prev " << prev_txid.substr(0, 16) << "..., vout=" << prev_vout << ")\n"
              << "  Outputs   : 1  → " << dst_addr << " (" << amount << " sats)\n"
              << "  Fee       : 1000 sats\n"
              << "  Locktime  : 0\n"
              << "  ScriptType: P2PKH\n";

    return 0;
}
