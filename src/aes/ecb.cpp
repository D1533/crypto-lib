#include "crypto/aes/ecb.hpp"

namespace crypto::cipher{

AES_ECB::AES_ECB(const std::array<uint8_t, 16>& key) : aes(key){

}

std::vector<uint8_t> AES_ECB::encrypt(const std::vector<uint8_t>& plaintext){
    std::array<uint8_t, 16> block;
    std::vector<uint8_t> ciphertext;

    std::vector<uint8_t> padded_plaintext = pkcs7_pad(plaintext);
    for (int block_n = 0; block_n < padded_plaintext.size(); block_n += 16){
        for (int i = 0; i < 16; i++)
            block[i] = padded_plaintext[block_n + i];
        std::array<uint8_t, 16> encrypted_block = aes.encrypt_block(block);
    
        for (int i = 0; i < 16; i++)
            ciphertext.push_back(encrypted_block[i]);   

    }
    
    return ciphertext;

}

std::vector<uint8_t> AES_ECB::decrypt(const std::vector<uint8_t>& ciphertext){
    std::array<uint8_t, 16> block;
    std::vector<uint8_t> plaintext;

    for (int block_n = 0; block_n < ciphertext.size(); block_n += 16){
        for (int i = 0; i < 16; i++)
            block[i] = ciphertext[block_n + i];
        std::array<uint8_t, 16> block_plaintext = aes.decrypt_block(block);
    
        for (int i = 0; i < 16; i++)
            plaintext.push_back(block_plaintext[i]);   

    }
    
    std::vector<uint8_t> unpadded_plaintext = pkcs7_unpad(plaintext);
    
    return unpadded_plaintext;

}

std::vector<uint8_t> AES_ECB::pkcs7_pad(const std::vector<uint8_t>& plaintext){
    size_t pad_len = 16 - (plaintext.size() % 16);
    std::vector<uint8_t> output = plaintext;

    for (size_t i = 0; i < pad_len; i++)
        output.push_back(static_cast<uint8_t>(pad_len));

    return output;
}

std::vector<uint8_t> AES_ECB::pkcs7_unpad(const std::vector<uint8_t>& data){
    if (data.empty() || data.size() % 16 != 0)
        throw std::runtime_error("Invalid padded data size");

    uint8_t pad = data.back();

    if (pad == 0 || pad > 16)
        throw std::runtime_error("Invalid padding value");

    // check all padding bytes
    for (size_t i = data.size() - pad; i < data.size(); i++) {
        if (data[i] != pad)
            throw std::runtime_error("Bad PKCS#7 padding");
    }

    return std::vector<uint8_t>(data.begin(), data.end() - pad);
}

std::vector<uint8_t> aes_ebc_encrypt(const std::vector<uint8_t>& plaintext, const std::array<uint8_t, 16>& key){
    AES_ECB cipher = AES_ECB(key);
    std::vector<uint8_t> encrypted_data = cipher.encrypt(plaintext);

    return encrypted_data;
}

std::vector<uint8_t> aes_ebc_decrypt(const std::vector<uint8_t>& ciphertext, const std::array<uint8_t, 16>& key){
    AES_ECB cipher = AES_ECB(key);
    std::vector<uint8_t> plaintext = cipher.decrypt(ciphertext);

    return plaintext;
}




}