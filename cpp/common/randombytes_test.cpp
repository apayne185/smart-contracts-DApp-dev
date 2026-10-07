// randombytes: sanity tests for the OS CSPRNG wrapper
//
// These cannot prove randomness; they catch wiring mistakes such as an
// unfilled buffer, a truncated large read, or a constant output.
#include "randombytes.h"
#include <array>
#include <iostream>
#include <string>
#include <vector>

static int passed = 0, failed = 0;

static void check(const std::string& label, bool ok) {
    if (ok) { std::cout << "PASS  " << label << "\n"; ++passed; }
    else    { std::cout << "FAIL  " << label << "\n"; ++failed; }
}

int main() {
    std::array<uint8_t, 32> a{}, b{};
    crypto::randombytes(a.data(), a.size());
    crypto::randombytes(b.data(), b.size());

    bool a_nonzero = false;
    for (auto x : a) a_nonzero |= (x != 0);
    check("32-byte output is not all zero", a_nonzero);
    check("two consecutive 32-byte outputs differ", a != b);

    // Larger than the 256-byte getentropy limit, exercising the chunk loop.
    std::vector<uint8_t> big(4096, 0);
    crypto::randombytes(big.data(), big.size());
    bool tail_nonzero = false;
    for (size_t i = big.size() - 32; i < big.size(); ++i) tail_nonzero |= (big[i] != 0);
    check("4 KiB request fills the tail of the buffer", tail_nonzero);

    crypto::randombytes(nullptr, 0);
    check("zero-length request is a no-op", true);

    std::cout << "\n" << passed << " passed, " << failed << " failed.\n";
    return failed > 0 ? 1 : 0;
}
