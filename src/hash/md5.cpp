
#include "crypto/hash/md5.hpp"
#include "crypto/internal/bitops.hpp"
#include <cstring>

namespace crypto::hash {

static const uint32_t K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
    0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
    0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
    0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
    0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
    0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
    0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
    0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
    0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

static const uint32_t S[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

MD5::MD5() {
    reset();
}

void MD5::reset() {
    state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;

    bitlen = 0;
    buffer_len = 0;
}

void MD5::update(const uint8_t* data, size_t len) {
    bitlen += len * 8;

    size_t i = 0;
    // fill existing buffer
    if (buffer_len > 0) {
        while (len > 0 && buffer_len < 64) {
            buffer[buffer_len++] = data[i++];
            len--;
        }

        if (buffer_len == 64) {
            compress(buffer);
            buffer_len = 0;
        }
    }

    // full blocks
    while (len >= 64) {
        compress(&data[i]);
        i += 64;
        len -= 64;
    }

    // remaining
    while (len > 0) {
        buffer[buffer_len++] = data[i++];
        len--;
    }
}
void MD5::compress(const uint8_t block[64]) {
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];

    uint32_t M[16];

    for (int i = 0; i < 16; i++) {
        M[i] = (uint32_t)block[i * 4]
             | ((uint32_t)block[i * 4 + 1] << 8)
             | ((uint32_t)block[i * 4 + 2] << 16)
             | ((uint32_t)block[i * 4 + 3] << 24);
    }

    for (int i = 0; i < 64; i++) {
        uint32_t f, g;

        if (i < 16) {
            f = (b & c) | ((~b) & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | ((~d) & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f =  c ^ (b | (~d));
            g = (7 * i) % 16;
        }

        f = f + a + K[i] + M[g];
        a = d;
        d = c;
        c = b;
        b = b + crypto::internal::rotl<uint32_t>(f, S[i]);

    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

std::array<uint8_t, 16> MD5::final() {

    buffer[buffer_len++] = 0x80;
    if ( buffer_len > 56){
        while (buffer_len < 64)
            buffer[buffer_len++] = 0x00;

        compress(buffer);
        buffer_len = 0;
    }
    while (buffer_len < 56)
        buffer[buffer_len++] = 0x00;

    uint64_t b = bitlen;
    for (int i = 0; i < 8; i++) {
        buffer[buffer_len++] = (uint8_t)(b >> (8 * i));
    }
    
    compress(buffer);
    std::array<uint8_t, 16> out;
    for (int i = 0; i < 4; i++) {
        out[i * 4 + 0] = (state[i] & 0xff);
        out[i * 4 + 1] = (state[i] >> 8) & 0xff;
        out[i * 4 + 2] = (state[i] >> 16) & 0xff;
        out[i * 4 + 3] = (state[i] >> 24) & 0xff;
    }

    reset();
    return out;
}


std::array<uint8_t, 16> md5(const uint8_t* data, size_t len) {
    MD5 md5;
    md5.update(data, len);
    return md5.final();
}

} 