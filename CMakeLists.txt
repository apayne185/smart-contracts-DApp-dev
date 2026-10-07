cmake_minimum_required(VERSION 3.16)
project(crypto-engines VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Build options. Defaults produce portable binaries; CI turns on WERROR.
option(CRYPTO_NATIVE_ARCH "Tune for the host CPU (-march=native); binaries are not portable" OFF)
option(CRYPTO_WERROR      "Treat compiler warnings as errors"                                OFF)
option(CRYPTO_SANITIZE    "Build with AddressSanitizer and UndefinedBehaviorSanitizer"       OFF)

find_package(Threads REQUIRED)

# Shared compile settings applied to every target via an interface library.
add_library(project_options INTERFACE)
target_compile_options(project_options INTERFACE -Wall -Wextra -Wpedantic -Wshadow)
if(CRYPTO_WERROR)
  target_compile_options(project_options INTERFACE -Werror)
endif()
if(CRYPTO_NATIVE_ARCH)
  target_compile_options(project_options INTERFACE -march=native)
endif()
if(CRYPTO_SANITIZE)
  target_compile_options(project_options INTERFACE
    -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  target_link_options(project_options INTERFACE -fsanitize=address,undefined)
endif()

# Helper: every target links project_options and sees cpp/ as its include root.
function(crypto_target name)
  target_link_libraries(${name} PRIVATE project_options)
  target_include_directories(${name} PUBLIC ${CMAKE_SOURCE_DIR}/cpp)
endfunction()

# ── Libraries ────────────────────────────────────────────────────────────────

# SHA-256 (FIPS 180-4), shared by pow and tx_builder
add_library(sha256 STATIC cpp/sha256/sha256.cpp)
crypto_target(sha256)

# SHA-3 / Keccak (FIPS 202), shared by SPHINCS+ and ML-KEM
add_library(sha3 STATIC cpp/sha3/sha3.cpp)
crypto_target(sha3)

# SPHINCS+ / SLH-DSA-SHAKE-128s (FIPS 205)
add_library(sphincs STATIC cpp/sphincs/sphincs.cpp)
crypto_target(sphincs)
target_link_libraries(sphincs PRIVATE sha3)

# ML-KEM-512 / CRYSTALS-Kyber (FIPS 203)
add_library(mlkem STATIC cpp/mlkem/mlkem.cpp)
crypto_target(mlkem)
target_link_libraries(mlkem PRIVATE sha3)

# ── Executables ──────────────────────────────────────────────────────────────

add_executable(pow cpp/pow/pow.cpp)
crypto_target(pow)
target_link_libraries(pow PRIVATE sha256 Threads::Threads)

add_executable(collision cpp/collision/collision.cpp)
crypto_target(collision)
target_link_libraries(collision PRIVATE Threads::Threads)

add_executable(tx_builder cpp/bitcoin/tx_builder.cpp)
crypto_target(tx_builder)
target_link_libraries(tx_builder PRIVATE sha256)

# ── Tests ────────────────────────────────────────────────────────────────────

enable_testing()

foreach(t sha256 sha3 sphincs mlkem)
  add_executable(${t}_test cpp/${t}/${t}_test.cpp)
  crypto_target(${t}_test)
  target_link_libraries(${t}_test PRIVATE ${t} sha3)
endforeach()

add_test(NAME sha256_vectors    COMMAND sha256_test)
add_test(NAME sha3_vectors      COMMAND sha3_test)
add_test(NAME sphincs_roundtrip COMMAND sphincs_test)
add_test(NAME mlkem_kat         COMMAND mlkem_test)
