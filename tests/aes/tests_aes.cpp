#include <iostream>
#include "crypto/aes/ecb.hpp"
#include "../tests/test_utils.hpp"
#include <iomanip>

void run_aes_ecb_tests(){
    // Encrypt tests
    test::run_symmetric_cipher_encrypt_test("AES", "AAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAA", "f8cba1aa5b5120b4f2fdda1b26ca01580515be1d9afb4c54a20390973f5828d8", crypto::cipher::aes_ebc_encrypt);
    test::run_symmetric_cipher_encrypt_test("AES", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "0123456789abcdef", "f583a539eee9d7911f3c5d5dde7f554a493e4951cdd5c83b2f1b1355950827eec6665f5cff77b502d6d42d9c90fb0e4dc40316fc9c0a4d11f6d1de2d90fba7c2", crypto::cipher::aes_ebc_encrypt);
    
    // Decrypt tests
    test::run_symmetric_cipher_decrypt_test("AES", "f8cba1aa5b5120b4f2fdda1b26ca01580515be1d9afb4c54a20390973f5828d8", "AAAAAAAAAAAAAAAA", test::to_hex(std::string("AAAAAAAAAAAAAAAA", 16)), crypto::cipher::aes_ebc_decrypt);
    test::run_symmetric_cipher_decrypt_test("AES", "f583a539eee9d7911f3c5d5dde7f554a493e4951cdd5c83b2f1b1355950827eec6665f5cff77b502d6d42d9c90fb0e4dc40316fc9c0a4d11f6d1de2d90fba7c2", "0123456789abcdef", test::to_hex(std::string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62)), crypto::cipher::aes_ebc_decrypt);
     
}

void run_aes_tests(){
    run_aes_ecb_tests();
}