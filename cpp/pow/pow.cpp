// Parallel SHA-256 proof-of-work prefix finder
//
// Finds the smallest N such that SHA256("bitcoin" + N) starts with a target prefix.
// Uses std::thread to partition the search space across all available CPU cores,
// with a shared std::atomic flag to halt all threads the moment one finds a match.
#include <atomic>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "../sha256/sha256.h"

struct Result {
    uint64_t    n;
    std::string input;
    std::string hex;
};

// Each thread searches n = start, start+stride, start+2*stride, ...
// until `found` flips true (another thread won) or it finds a match itself.
static void search_worker(
    const std::string&   prefix,
    uint64_t             start,
    uint64_t             stride,
    std::atomic<bool>&   found,
    std::atomic<Result*>& result)
{
    for (uint64_t n = start; !found.load(std::memory_order_relaxed); n += stride) {
        std::string candidate = "bitcoin" + std::to_string(n);
        auto digest = sha256::hash(candidate);
        auto hex    = sha256::to_hex(digest);

        if (hex.compare(0, prefix.size(), prefix) == 0) {
            // Only the first thread to win stores the result
            bool expected = false;
            if (found.compare_exchange_strong(expected, true)) {
                result.store(new Result{n, candidate, hex});
            }
            return;
        }
    }
}

static Result find_prefix(const std::string& prefix) {
    const unsigned int nthreads = std::thread::hardware_concurrency();

    std::atomic<bool>    found{false};
    std::atomic<Result*> result{nullptr};

    std::vector<std::thread> threads;
    threads.reserve(nthreads);

    for (unsigned int t = 0; t < nthreads; ++t)
        threads.emplace_back(search_worker, std::cref(prefix), t, nthreads,
                             std::ref(found), std::ref(result));

    for (auto& th : threads) th.join();

    Result r = *result.load();
    delete result.load();
    return r;
}

int main(int argc, char* argv[]) {
    // Accept optional target prefixes as arguments; defaults to the full benchmark suite.
    // Example: ./pow cafe faded      (quick)
    //          ./pow                 (full: cafe, faded, decade)
    const std::vector<std::string> targets =
        (argc > 1)
            ? std::vector<std::string>(argv + 1, argv + argc)
            : std::vector<std::string>{"cafe", "faded", "decade"};

    const unsigned int nthreads = std::thread::hardware_concurrency();

    std::cout << "Parallel SHA-256 PoW prefix finder\n";
    std::cout << "Threads: " << nthreads << "\n\n";

    for (const auto& target : targets) {
        std::cout << "Searching for prefix '" << target << "' ...\n";

        auto t0 = std::chrono::high_resolution_clock::now();
        auto r  = find_prefix(target);
        auto t1 = std::chrono::high_resolution_clock::now();

        double elapsed = std::chrono::duration<double>(t1 - t0).count();

        std::cout << "  Found:   " << r.input << "\n";
        std::cout << "  Hash:    " << r.hex << "\n";
        std::cout << "  N:       " << r.n << "\n";
        std::cout << "  Time:    " << std::fixed << std::setprecision(4) << elapsed << "s\n";
        std::cout << "  Rate:    ~" << uint64_t(double(r.n + 1) / elapsed / 1e6)
                  << " MH/s\n\n";
    }

    return 0;
}
