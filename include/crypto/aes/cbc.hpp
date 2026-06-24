#pragma once

#include <array>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <vector>
#include "crypto/aes/aes.hpp"

namespace crypto::cipher{

class AES_CBC {
public:
    AES_CBC(const std::vector<uint8_t> &key, const std::array<uint8_t, 16> &iv);

    std::vector<uint8_t> pkcs7_pad(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> pkcs7_unpad(const std::vector<uint8_t>& plaintext);

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext);


private:
    AES aes;
    std::array<uint8_t, 16> iv;
};

}
