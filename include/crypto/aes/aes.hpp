#pragma once

#include <array>
#include <vector>
#include <cstdint>
#include <stdexcept>


namespace crypto::cipher{
class AES {
public:
    static constexpr size_t BlockSize = 16; 

    enum class KeySize { AES128 = 16, AES192 = 24, AES256 = 32};

    explicit AES(const std::array<uint8_t, 16> &key); // AES 128
    //explicit AES(const std::array<uint8_t, 24> &key); // AES 192
    //explicit AES(const std::array<uint8_t, 32> &key); // AES 256
    

    // Encrypt / Decrypt single 16-byte block
    std::array<uint8_t, BlockSize> encrypt_block(const std::array<uint8_t, BlockSize>& input);
    std::array<uint8_t, BlockSize> decrypt_block(const std::array<uint8_t, BlockSize>& input);


private:
    KeySize key_size;
    int rounds;
    std::vector<std::array<uint8_t, 16>> round_keys;

private:
    void key_expansion(const std::array<uint8_t, 16>& key);

    void add_round_key(std::array<uint8_t, 16>& state, int round);

    void sub_bytes(std::array<uint8_t, 16>& state);
    void inv_sub_bytes(std::array<uint8_t, 16>& state);

    void shift_rows(std::array<uint8_t, 16>& state);
    void inv_shift_rows(std::array<uint8_t, 16>& state);

    void mix_columns(std::array<uint8_t, 16>& state);
    void inv_mix_columns(std::array<uint8_t, 16>& state);

};

}