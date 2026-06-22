#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace sha256 {

// SHA-256 digest is 32 bytes / 256 bits
using Digest = std::array<uint8_t, 32>;

// Hash a raw byte buffer
Digest hash(const uint8_t* data, size_t len);

// Hash a string
Digest hash(const std::string& s);

// Hex-encode a digest
std::string to_hex(const Digest& d);

} // namespace sha256
