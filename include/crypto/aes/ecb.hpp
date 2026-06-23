#pragma once

#include <array>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <vector>
#include "crypto/aes/aes.hpp"

namespace crypto::cipher{

class AES_ECB {
public:
    AES_ECB(const std::array<uint8_t, 16> &key);

    std::vector<uint8_t> pkcs7_pad(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> pkcs7_unpad(const std::vector<uint8_t>& plaintext);

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext);


private:
    AES aes;
};


std::vector<uint8_t> aes_ebc_encrypt(const std::vector<uint8_t>& plaintext, const std::array<uint8_t, 16>& key);
std::vector<uint8_t> aes_ebc_decrypt(const std::vector<uint8_t>& ciphertext, const std::array<uint8_t, 16>& key);



}