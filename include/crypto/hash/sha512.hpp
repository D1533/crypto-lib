#pragma once

#include <cstdint>
#include <cstddef>
#include <array>

namespace crypto::hash{

class SHA512{
public:
    SHA512();
    void update(const uint8_t *data, size_t len);
    std::array<uint8_t, 64> final();
    void reset();

private:
    void compress(const uint8_t block[128]);

private:
    uint64_t state[8];
    uint64_t bitlen;
    uint8_t buffer[128];
    size_t buffer_len;

};

std::array<uint8_t, 64> sha512(const uint8_t* data, size_t len);

}