// encryptor.cpp
// v0.15.0 (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

// Define the implementation flag BEFORE including the header
#define CHACHA20_IMPLEMENTATION
#include "..\libs\chacha\chacha20.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>

// A 256-bit (32-byte) key.
static const uint8_t thek[32] = {
    0x3b, 0x15, 0xe7, 0xea, 0x46, 0x7f, 0x7d, 0x5d, 
    0x33, 0xd9, 0x51, 0xe3, 0xc9, 0x6c, 0x5d, 0x1d, 
    0xa4, 0x95, 0x28, 0x47, 0xa1, 0xb7, 0xb2, 0x6d, 
    0x14, 0x93, 0x1e, 0x4e, 0xed, 0x2, 0x68, 0xa3};

// A 96-bit (12-byte) nonce.
static const uint8_t theN[12] = {
     0x3a, 0xc4, 0x29, 0xdc, 0xfd, 0xed, 0xca, 0x35, 0x0, 0x2, 0x82, 0x51};

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        std::cerr << "Usage: " << argv[0] << " <input_file> <output_file>" << std::endl;
        return 1;
    }

    std::ifstream inFile(argv[1], std::ios::binary);
    if (!inFile)
    {
        std::cerr << "Error opening input file: " << argv[1] << std::endl;
        return 1;
    }

    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    // Encrypt the buffer in-place using our new function
    chacha20_xor(thek, theN, buffer.data(), buffer.size(), 0);

    std::ofstream outFile(argv[2], std::ios::binary);
    if (!outFile)
    {
        std::cerr << "Error opening output file: " << argv[2] << std::endl;
        return 1;
    }

    outFile.write(reinterpret_cast<const char *>(buffer.data()), buffer.size());
    outFile.close();

    std::cout << "Successfully ChaCha20-encrypted " << argv[1] << " to " << argv[2] << std::endl;
    return 0;
}