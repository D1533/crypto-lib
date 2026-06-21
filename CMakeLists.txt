cmake_minimum_required(VERSION 3.16)
project(crypto_lib CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# -------------------------
# Crypto library
# -------------------------
add_library(crypto
src/hash/md5.cpp
src/hash/sha1.cpp
src/hash/sha256.cpp
src/hash/sha512.cpp
src/hash/sha384.cpp
)

target_include_directories(crypto PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)


# -------------------------
# Test executable
# -------------------------
add_executable(tests
    tests/tests_main.cpp
    tests/hash/tests_hash.cpp
)

target_link_libraries(tests PRIVATE crypto)

target_include_directories(tests PRIVATE
    ${CMAKE_SOURCE_DIR}/tests
)