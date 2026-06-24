#include <iostream>
#include "crypto/aes/ecb.hpp"
#include "crypto/aes/cbc.hpp"
#include "../tests/test_utils.hpp"
#include <iomanip>

void run_aes_ecb_tests(){
    crypto::cipher::AES_ECB aes_ecb(test::to_vector("AAAAAAAAAAAAAAAA"));
    test::run_symmetric_cipher_encrypt_test("AES_ECB", "AAAAAAAAAAAAAAAA", "f8cba1aa5b5120b4f2fdda1b26ca01580515be1d9afb4c54a20390973f5828d8", aes_ecb);
    test::run_symmetric_cipher_decrypt_test("AES_ECB", "f8cba1aa5b5120b4f2fdda1b26ca01580515be1d9afb4c54a20390973f5828d8", test::to_hex(std::string("AAAAAAAAAAAAAAAA", 16)), aes_ecb);
    
    aes_ecb = crypto::cipher::AES_ECB(test::to_vector("0123456789abcdef"));
    test::run_symmetric_cipher_encrypt_test("AES_ECB", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "f583a539eee9d7911f3c5d5dde7f554a493e4951cdd5c83b2f1b1355950827eec6665f5cff77b502d6d42d9c90fb0e4dc40316fc9c0a4d11f6d1de2d90fba7c2", aes_ecb);
    test::run_symmetric_cipher_decrypt_test("AES_ECB", "f583a539eee9d7911f3c5d5dde7f554a493e4951cdd5c83b2f1b1355950827eec6665f5cff77b502d6d42d9c90fb0e4dc40316fc9c0a4d11f6d1de2d90fba7c2", test::to_hex(std::string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62)), aes_ecb);
    
}

void run_aes_cbc_tests(){
    crypto::cipher::AES_CBC aes_cbc(test::to_vector("AAAAAAAAAAAAAAAA"), test::to_array16("AAAAAAAAAAAAAAAA"));
    test::run_symmetric_cipher_encrypt_test("AES_CBC", "AAAAAAAAAAAAAAAA", "81d6cdc3bd16fb8d72b9bb88818b5be9f4226b3d632aeaff38731fbb288efbf5", aes_cbc);
    test::run_symmetric_cipher_decrypt_test("AES_CBC", "81d6cdc3bd16fb8d72b9bb88818b5be9f4226b3d632aeaff38731fbb288efbf5", test::to_hex(std::string("AAAAAAAAAAAAAAAA", 16)), aes_cbc);
   
    aes_cbc = crypto::cipher::AES_CBC(test::to_vector("0123456789abcdef"), test::to_array16("ABCDEFGHIJKLMNOP"));
    test::run_symmetric_cipher_encrypt_test("AES_CBC", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "0b9b15da4b44a0f5151dcfc4c01f35d56fafb03339e4b0c7fedbc2546f941ddda7424d4e189f5e267fba1306c5de507a17a2840f477dd267fcce243835e2dc88", aes_cbc);
    test::run_symmetric_cipher_decrypt_test("AES_CBC", "0b9b15da4b44a0f5151dcfc4c01f35d56fafb03339e4b0c7fedbc2546f941ddda7424d4e189f5e267fba1306c5de507a17a2840f477dd267fcce243835e2dc88", test::to_hex(std::string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62)), aes_cbc);
     
}


void run_aes_tests(){
    run_aes_ecb_tests();
    run_aes_cbc_tests();
}