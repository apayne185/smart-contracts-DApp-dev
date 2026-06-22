// Birthday attack collision finder for the djb2-variant hash (hash1)
//
// The target hash function (ported from the Python assignment) maps an ASCII
// string to a 32-bit value using the djb2 recurrence:
//
//   hash = ((hash << 5) - hash + ord(c)) & 0xFFFFFFFF
//
// With only 2^32 possible outputs, the birthday bound guarantees a collision
// after ~2^16 (~65 536) random inputs in expectation. This implementation
// uses std::unordered_map for O(1) average lookup and std::mt19937 for fast
// pseudo-random string generation. A parallel variant partitions the random
// search across threads and merges tables when a cross-thread collision is found.
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

// ── Target hash function (mirrors hash1.py) ──────────────────────────────────

static uint32_t djb2_hash(const std::string& s) {
    uint32_t h = 0;
    for (unsigned char c : s)
        h = ((h << 5) - h) + c; // h * 31 + c  (mod 2^32 implicitly)
    return h;
}

// ── Random printable ASCII string generator ───────────────────────────────────

static std::string random_string(std::mt19937& rng, int length = 8) {
    // Printable ASCII: 0x20–0x7E (95 chars, matching Python's string.printable[:94])
    static constexpr char CHARS[] =
        " !\"#$%&'()*+,-./0123456789:;<=>?@"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
        "abcdefghijklmnopqrstuvwxyz{|}~";
    static constexpr int NCHARS = 94;

    std::uniform_int_distribution<int> dist(0, NCHARS - 1);
    std::string out(length, ' ');
    for (char& c : out) c = CHARS[dist(rng)];
    return out;
}

// ── Single-threaded search (simple, clear, fast enough for demo) ──────────────

static void find_collision_single() {
    std::unordered_map<uint32_t, std::string> seen;
    seen.reserve(1 << 17); // pre-size past the birthday bound

    std::mt19937 rng{std::random_device{}()};
    uint64_t attempts = 0;

    auto t0 = std::chrono::high_resolution_clock::now();

    while (true) {
        std::string s = random_string(rng);
        uint32_t    h = djb2_hash(s);
        ++attempts;

        auto it = seen.find(h);
        if (it != seen.end() && it->second != s) {
            auto t1 = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double>(t1 - t0).count();

            std::cout << "Collision found after " << attempts << " attempts ("
                      << std::fixed << elapsed << "s)\n\n";
            std::cout << "  String A : \"" << it->second << "\"\n";
            std::cout << "  String B : \"" << s          << "\"\n";
            std::cout << "  Hash     : 0x" << std::hex << h << std::dec << "\n\n";

            // Verify
            std::cout << "Verification:\n";
            std::cout << "  djb2(\"" << it->second << "\") = 0x" << std::hex << djb2_hash(it->second) << "\n";
            std::cout << "  djb2(\"" << s          << "\") = 0x" << djb2_hash(s) << std::dec << "\n";
            return;
        }
        seen[h] = s;
    }
}

// ── Parallel search — threads share a global table behind a mutex ─────────────
// For 32-bit hashes this is optional (single-thread finds collisions in <1s),
// but it demonstrates the threading pattern for larger hash spaces.

static std::mutex              g_table_mutex;
static std::unordered_map<uint32_t, std::string> g_table;
static std::atomic<bool>       g_found{false};

struct CollisionResult { std::string a, b; uint32_t h; uint64_t attempts; };
static CollisionResult g_result;

static void parallel_worker(int seed, uint64_t attempts_per_batch = 512) {
    std::mt19937 rng{uint32_t(seed)};
    uint64_t local_attempts = 0;

    // Each thread builds a local batch, then merges under lock
    std::vector<std::pair<uint32_t, std::string>> batch;
    batch.reserve(attempts_per_batch);

    while (!g_found.load(std::memory_order_relaxed)) {
        batch.clear();
        for (uint64_t i = 0; i < attempts_per_batch; ++i) {
            std::string s = random_string(rng);
            batch.push_back({djb2_hash(s), std::move(s)});
            ++local_attempts;
        }

        std::lock_guard<std::mutex> lock(g_table_mutex);
        for (auto& [h, s] : batch) {
            auto it = g_table.find(h);
            if (it != g_table.end() && it->second != s) {
                bool expected = false;
                if (g_found.compare_exchange_strong(expected, true)) {
                    g_result = {it->second, s, h, local_attempts};
                }
                return;
            }
            g_table[h] = s;
        }
    }
}

static void find_collision_parallel() {
    const unsigned int nthreads = std::thread::hardware_concurrency();
    g_table.reserve(1 << 17);

    std::cout << "Running parallel search on " << nthreads << " threads...\n\n";

    auto t0 = std::chrono::high_resolution_clock::now();

    std::vector<std::thread> threads;
    threads.reserve(nthreads);
    for (unsigned int i = 0; i < nthreads; ++i)
        threads.emplace_back([i]{ parallel_worker(int(i + 1)); });
    for (auto& th : threads) th.join();

    auto t1 = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double>(t1 - t0).count();

    uint64_t total = g_table.size();
    std::cout << "Collision found after ~" << total << " total insertions ("
              << elapsed << "s)\n\n";
    std::cout << "  String A : \"" << g_result.a << "\"\n";
    std::cout << "  String B : \"" << g_result.b << "\"\n";
    std::cout << "  Hash     : 0x" << std::hex << g_result.h << std::dec << "\n";
}

int main(int argc, char* argv[]) {
    bool parallel = (argc > 1 && std::string(argv[1]) == "--parallel");

    std::cout << "Birthday Attack — djb2 32-bit hash collision finder\n";
    std::cout << "====================================================\n\n";

    if (parallel)
        find_collision_parallel();
    else
        find_collision_single();

    return 0;
}
