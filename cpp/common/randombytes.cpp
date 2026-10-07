#include "randombytes.h"

#include <cerrno>
#include <stdexcept>

#if defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <unistd.h>
#else
#error "randombytes: unsupported platform (need getrandom or getentropy)"
#endif

namespace crypto {

void randombytes(uint8_t* out, size_t n) {
#if defined(__linux__)
    // getrandom may return fewer bytes than requested for large n, or be
    // interrupted by a signal; loop until the buffer is full.
    while (n > 0) {
        ssize_t r = getrandom(out, n, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error("randombytes: getrandom failed");
        }
        out += r;
        n   -= static_cast<size_t>(r);
    }
#else
    // getentropy is limited to 256 bytes per call.
    while (n > 0) {
        size_t chunk = n < 256 ? n : 256;
        if (getentropy(out, chunk) != 0)
            throw std::runtime_error("randombytes: getentropy failed");
        out += chunk;
        n   -= chunk;
    }
#endif
}

} // namespace crypto
