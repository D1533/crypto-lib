#pragma once

#include <cstdint>
#include <cstddef>
#include <array>


namespace crypto::hash{

class SHA1{
public:
    SHA1();
    void update(const uint8_t *data, size_t len);
    std::array<uint8_t, 20> final(); 
    void reset();

private:
    void compress(const uint8_t block[64]);
private:
    uint32_t state[5];
    uint64_t bitlen;
    uint8_t buffer[64];
    size_t buffer_len;
};

std::array<uint8_t, 20> sha1(const uint8_t* data, size_t len);

}