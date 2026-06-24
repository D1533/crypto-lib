#include "crypto/aes/cbc.hpp"

namespace crypto::cipher{

AES_CBC::AES_CBC(const std::vector<uint8_t>& key, const std::array<uint8_t, 16>& iv) : aes(key), iv(iv){

}

std::vector<uint8_t> AES_CBC::encrypt(const std::vector<uint8_t>& plaintext){
    
    std::array<uint8_t, 16> block;
    std::array<uint8_t, 16> curr_iv = iv;
    std::vector<uint8_t> padded_plaintext = pkcs7_pad(plaintext);
    
    std::vector<uint8_t> ciphertext;
    ciphertext.reserve(padded_plaintext.size());
    
    for (size_t block_n = 0; block_n < padded_plaintext.size(); block_n += 16){
        
        for (size_t i = 0; i < 16; i++)
            block[i] = padded_plaintext[block_n + i] ^ curr_iv[i];

        std::array<uint8_t, 16> encrypted_block = aes.encrypt_block(block);
        curr_iv = encrypted_block;

        ciphertext.insert(ciphertext.end(), encrypted_block.begin(), encrypted_block.end());

    }
    
    return ciphertext;

}

std::vector<uint8_t> AES_CBC::decrypt(const std::vector<uint8_t>& ciphertext){
    
    std::array<uint8_t, 16> block;
    std::array<uint8_t, 16> curr_iv = iv;

    std::vector<uint8_t> plaintext;
    plaintext.reserve(ciphertext.size());

    for (size_t block_n = 0; block_n < ciphertext.size(); block_n += 16){

        for (size_t i = 0; i < 16; i++)
            block[i] = ciphertext[block_n + i];
       
        std::array<uint8_t, 16> block_plaintext = aes.decrypt_block(block);
        for (size_t i = 0; i < 16; i++)
            block_plaintext[i] ^= curr_iv[i];
        
        plaintext.insert(plaintext.end(), block_plaintext.begin(), block_plaintext.end());
        curr_iv = block;
    }
    
    std::vector<uint8_t> unpadded_plaintext = pkcs7_unpad(plaintext);
    
    return unpadded_plaintext;

}

std::vector<uint8_t> AES_CBC::pkcs7_pad(const std::vector<uint8_t>& plaintext){
    size_t pad_len = 16 - (plaintext.size() % 16);
    std::vector<uint8_t> output = plaintext;

    for (size_t i = 0; i < pad_len; i++)
        output.push_back(static_cast<uint8_t>(pad_len));

    return output;
}

std::vector<uint8_t> AES_CBC::pkcs7_unpad(const std::vector<uint8_t>& plaintext){
    if (plaintext.empty() || plaintext.size() % 16 != 0)
        throw std::runtime_error("Invalid padded data size");

    uint8_t pad = plaintext.back();

    if (pad == 0 || pad > 16)
        throw std::runtime_error("Invalid padding value");

    // check all padding bytes
    for (size_t i = plaintext.size() - pad; i < plaintext.size(); i++) {
        if (plaintext[i] != pad)
            throw std::runtime_error("Bad PKCS#7 padding");
    }

    return std::vector<uint8_t>(plaintext.begin(), plaintext.end() - pad);
}

}