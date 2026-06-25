cmake_minimum_required(VERSION 3.16)
project(crypto-engines LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG   "-O0 -g -fsanitize=address,undefined")

find_package(Threads REQUIRED)

# SHA-256 — shared by pow and tx_builder
add_library(sha256 STATIC cpp/sha256/sha256.cpp)
target_include_directories(sha256 PUBLIC ${CMAKE_SOURCE_DIR}/cpp)

# Parallel SHA-256 proof-of-work prefix finder
add_executable(pow cpp/pow/pow.cpp)
target_link_libraries(pow PRIVATE sha256 Threads::Threads)

# Birthday attack collision finder on djb2 32-bit hash
add_executable(collision cpp/collision/collision.cpp)
target_link_libraries(collision PRIVATE Threads::Threads)

# Raw Bitcoin P2PKH transaction builder
add_executable(tx_builder cpp/bitcoin/tx_builder.cpp)
target_link_libraries(tx_builder PRIVATE sha256)

# SHA-3 / Keccak — shared by future PQC modules (SPHINCS+, Kyber)
add_library(sha3 STATIC cpp/sha3/sha3.cpp)
target_include_directories(sha3 PUBLIC ${CMAKE_SOURCE_DIR}/cpp)

# SHA-256 known-answer tests (NIST FIPS 180-4 vectors)
add_executable(sha256_test cpp/sha256/sha256_test.cpp)
target_link_libraries(sha256_test PRIVATE sha256)

# SHA-3 / Keccak known-answer tests (NIST FIPS 202 vectors)
add_executable(sha3_test cpp/sha3/sha3_test.cpp)
target_link_libraries(sha3_test PRIVATE sha3)

enable_testing()
add_test(NAME sha256_vectors COMMAND sha256_test)
add_test(NAME sha3_vectors   COMMAND sha3_test)
