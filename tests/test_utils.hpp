#pragma once

#include <array>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <cstdint>
#include <string>
#include <vector>

namespace test {

template <typename Container>
inline std::string to_hex(const Container& c) {
    std::ostringstream oss;

    for (auto b : c) {
        oss << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(b);
    }

    return oss.str();
}


inline std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;

    if (hex.size() % 2 != 0) {
        throw std::runtime_error("Invalid hex length");
    }

    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

template <typename HashFunc>
void run_hash_test(const std::string& name, const std::string& input, const std::string& expected, HashFunc hash){
    auto result = hash(reinterpret_cast<const uint8_t*>(input.data()), input.size());

    std::string hex = to_hex(result);

    if (hex != expected) {
        std::cout << "[" << name << "] FAIL\n";
        std::cout << "Input:  " << input << "\n";
        std::cout << "Got:    " << hex << "\n";
        std::cout << "Expect: " << expected << "\n";
    } else {
        std::cout << "[" << name << "] OK\n";
    }
}

template <typename Cipher>
void run_symmetric_cipher_encrypt_test(const std::string& name, const std::string& input, const std::string& key, const std::string& expected, Cipher cipher){
    std::vector<uint8_t> input_v(input.begin(), input.end());
    std::array<uint8_t, 16> key_v{};
    std::copy(key.begin(), key.end(), key_v.begin());
    auto result = cipher(input_v, key_v);

    std::string hex = to_hex(result);

    if (hex != expected) {
        std::cout << "[" << name << "] FAIL\n";
        std::cout << "Input:  " << input << "\n";
        std::cout << "Got:    " << hex << "\n";
        std::cout << "Expect: " << expected << "\n";
    } else {
        std::cout << "[" << name << "] OK\n";
    }

    
}

template <typename Cipher>
void run_symmetric_cipher_decrypt_test(const std::string& name, const std::string& input, const std::string& key, const std::string& expected, Cipher cipher){
    std::vector<uint8_t> input_v = hex_to_bytes(input);

    std::array<uint8_t, 16> key_v{};
    std::copy(key.begin(), key.end(), key_v.begin());

    auto result = cipher(input_v, key_v);

    std::string hex = to_hex(result);

    if (hex != expected) {
        std::cout << "[" << name << "] FAIL\n";
        std::cout << "Input:  " << input << "\n";
        std::cout << "Got:    " << hex << "\n";
        std::cout << "Expect: " << expected << "\n";
    } else {
        std::cout << "[" << name << "] OK\n";
    }
}


}