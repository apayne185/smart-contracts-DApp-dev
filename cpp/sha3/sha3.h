#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace sha3 {

using Digest256 = std::array<uint8_t, 32>;
using Digest512 = std::array<uint8_t, 64>;

// SHA3-256: 1088-bit rate, 512-bit capacity, 256-bit output (FIPS 202)
Digest256 sha3_256(const uint8_t* data, size_t len);
Digest256 sha3_256(std::string_view s);

// SHA3-512: 576-bit rate, 1024-bit capacity, 512-bit output (FIPS 202)
Digest512 sha3_512(const uint8_t* data, size_t len);
Digest512 sha3_512(std::string_view s);

// SHAKE128: 1344-bit rate, 256-bit capacity, variable output (FIPS 202)
std::vector<uint8_t> shake128(const uint8_t* data, size_t len, size_t outbytes);
std::vector<uint8_t> shake128(std::string_view s, size_t outbytes);

// SHAKE256: 1088-bit rate, 512-bit capacity, variable output (FIPS 202)
std::vector<uint8_t> shake256(const uint8_t* data, size_t len, size_t outbytes);
std::vector<uint8_t> shake256(std::string_view s, size_t outbytes);

template <size_t N>
std::string to_hex(const std::array<uint8_t, N>& d);
std::string to_hex(const std::vector<uint8_t>& d);
std::string to_hex(const uint8_t* data, size_t len);

} // namespace sha3
