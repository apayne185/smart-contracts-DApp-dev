// randombytes: operating-system CSPRNG wrapper
//
// Single entry point for cryptographic randomness used by the PQC engines
// (SPHINCS+ signing randomisers, ML-KEM / SPHINCS+ key seeds).
//
//   Linux        getrandom(2), blocks only until the kernel pool is seeded
//   macOS / BSD  getentropy(3), requested in 256-byte chunks
//
// Throws std::runtime_error if the OS source fails. Never falls back to a
// non-cryptographic generator.
#pragma once
#include <cstddef>
#include <cstdint>

namespace crypto {

void randombytes(uint8_t* out, size_t n);

} // namespace crypto
