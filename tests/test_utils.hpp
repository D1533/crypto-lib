#pragma once

#include <array>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <cstdint>
#include <string>
#include <vector>

namespace test {

template <size_t N>
std::string to_hex(const std::array<uint8_t, N>& h) {
    std::ostringstream oss;

    for (auto b : h) {
        oss << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(b);
    }

    return oss.str();
}

template <typename HashFunc>
void run_test(const std::string& name, const std::string& input, const std::string& expected, HashFunc hash){
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

}