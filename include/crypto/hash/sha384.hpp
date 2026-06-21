#pragma once

#include <cstdint>
#include <cstddef>
#include <array>

namespace crypto::hash{

class SHA384{
public:
    SHA384();
    void update(const uint8_t *data, size_t len);
    std::array<uint8_t, 48> final();
    void reset();

private:
    void compress(const uint8_t block[128]);

private:
    uint64_t state[8];
    uint64_t bitlen;
    uint8_t buffer[128];
    size_t buffer_len;

};

std::array<uint8_t, 48> sha384(const uint8_t* data, size_t len);

}