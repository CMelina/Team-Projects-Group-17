

#ifndef SECURE_TRANSFER_H
#define SECURE_TRANSFER_H

#include <string>

// Encrypt file → outputs encrypted file
bool secure_encrypt_file(
    const std::string& input_path,
    const std::string& output_path,
    const std::string& key_string
);

// Decrypt file → restores original
bool secure_decrypt_file(
    const std::string& input_path,
    const std::string& output_path,
    const std::string& key_string
);

#endif
