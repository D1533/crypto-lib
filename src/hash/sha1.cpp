#include "crypto/hash/sha1.hpp"
#include "crypto/internal/bitops.hpp"

namespace crypto::hash{

SHA1::SHA1(){
    reset();
}

void SHA1::reset(){
    state[0] = 0x67452301;
    state[1] = 0xEFCDAB89;
    state[2] = 0x98BADCFE;
    state[3] = 0x10325476;
    state[4] = 0xC3D2E1F0;

    bitlen = 0;
    buffer_len = 0;
}

void SHA1::update(const uint8_t *data, size_t len){
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


void SHA1::compress(const uint8_t block[64]){

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    
    uint32_t w[80];
    for (int i = 0; i < 16; i++){
        w[i] =  ((uint32_t)block[i*4] << 24) |
                ((uint32_t)block[i*4 + 1] << 16) |
                ((uint32_t)block[i*4 + 2] << 8)  |
                ((uint32_t)block[i*4 + 3]);
    }

    for (int i = 16; i < 80; i++){
        w[i] = crypto::internal::rotl<uint32_t>((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1);
    }

    for (int i = 0; i < 80; i++){
        uint32_t f, k;
        
        if (i < 20){
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        }
        else if(i < 40){
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        }
        else if(i < 60){
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        }
        else{
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        uint32_t temp = crypto::internal::rotl<uint32_t>(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = crypto::internal::rotl<uint32_t>(b, 30);
        b = a;
        a = temp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

}

std::array<uint8_t, 20> SHA1::final() {

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
    for (int i = 7; i >= 0; i--) {
        buffer[buffer_len++] = (b >> (8 * i)) & 0xff;
    } 
    
    compress(buffer);
    std::array<uint8_t, 20> out;
    for (int i = 0; i < 5; i++) {
        out[i * 4 + 0] = (state[i] >> 24) & 0xff;
        out[i * 4 + 1] = (state[i] >> 16) & 0xff;
        out[i * 4 + 2] = (state[i] >> 8) & 0xff;
        out[i * 4 + 3] = (state[i] >> 0) & 0xff;
    }

    reset();
    return out;
}

std::array<uint8_t, 20> sha1(const uint8_t* data, size_t len) {
    SHA1 sha1;
    sha1.update(data, len);
    return sha1.final();
}


}