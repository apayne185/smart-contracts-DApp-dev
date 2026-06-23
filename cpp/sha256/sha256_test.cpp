// SHA-256 known-answer tests against NIST FIPS 180-4 test vectors.
// Exits 0 on pass, 1 on any failure — suitable for CI.
#include "sha256.h"
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

struct Vector { std::string input; std::string expected_hex; };

static const std::vector<Vector> VECTORS = {
    // FIPS 180-4 examples + well-known values
    { "",
      "e3b0c44298fc1c149afbf4c8996fb924"
      "27ae41e4649b934ca495991b7852b855" },
    { "abc",
      "ba7816bf8f01cfea414140de5dae2223"
      "b00361a396177a9cb410ff61f20015ad" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "248d6a61d20638b8e5c026930c3e6039"
      "a33ce45964ff2167f6ecedd419db06c1" },
    // Bitcoin-relevant: double-SHA256 of empty string
    { "bitcoin",
      "6b88c087247aa2f07ee1c5956b8e1a9f"
      "4c7f892a70e324f1bb3d161e05ca107b" },
    // 55-byte input (one byte short of a full block before padding)
    { std::string(55, 'a'),
      "9f4390f8d30c2dd92ec9f095b65e2b9a"
      "e9b0a925a5258e241c9f1e910f734318" },
    // 56-byte input (forces a two-block padding)
    { std::string(56, 'a'),
      "b35439a4ac6f0948b6d6f9e3c6af0f5f"
      "590ce20f1bde7090ef7970686ec6738a" },
};

int main() {
    int passed = 0, failed = 0;

    for (const auto& v : VECTORS) {
        auto digest = sha256::hash(v.input);
        auto hex    = sha256::to_hex(digest);

        if (hex == v.expected_hex) {
            std::cout << "PASS  sha256(\"" << v.input.substr(0, 20)
                      << (v.input.size() > 20 ? "..." : "") << "\")\n";
            ++passed;
        } else {
            std::cout << "FAIL  sha256(\"" << v.input.substr(0, 20) << "\")\n"
                      << "      expected: " << v.expected_hex << "\n"
                      << "      got:      " << hex << "\n";
            ++failed;
        }
    }

    std::cout << "\n" << passed << " passed, " << failed << " failed.\n";
    return failed > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
