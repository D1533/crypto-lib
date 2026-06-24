

## Crypto Library

## Introduction

This project implements core cryptographic primitives from scratch in C++ for educational purposes, 
with a focus on understanding the underlying mathematical and algorithmic foundations of cryptography.

## Current implementations

Hash: MD5, SHA1, SHA256, SHA384, SHA256.
AES: ECB, CBC


## Project Structure

```bash
crypto-lib/
├── build
├── include
│   └── crypto
│       ├── aes
│       │   ├── aes.hpp
│       │   ├── cbc.hpp
│       │   └── ecb.hpp
│       ├── hash
│       │   ├── md5.hpp
│       │   ├── sha1.hpp
│       │   ├── sha256.hpp
│       │   ├── sha384.hpp
│       │   └── sha512.hpp
│       └── internal
│           └── bitops.hpp
├── src
│   ├── aes
│   │   ├── aes.cpp
│   │   ├── cbc.cpp
│   │   └── ecb.cpp
│   └── hash
│       ├── md5.cpp
│       ├── sha1.cpp
│       ├── sha256.cpp
│       ├── sha384.cpp
│       └── sha512.cpp
└── tests
    ├── aes
    │   └── tests_aes.cpp
    ├── hash
    │   └── tests_hash.cpp
    ├── tests_main.cpp
    └── test_utils.hpp
```


