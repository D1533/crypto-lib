#pragma once

#include <cstdint>


namespace crypto::internal{

    template<typename T>
    inline constexpr T rotl(T x, unsigned int c){
        constexpr unsigned bits = sizeof(T) * 8;
        c %= bits;
        return (x << c) | (x >> (bits - c));
    }

    template<typename T>
    inline constexpr T rotr(T x, unsigned int c){
        constexpr unsigned bits = sizeof(T) * 8;
        c %= bits;
        return (x << (bits - c)) | (x >> c);
    }

}