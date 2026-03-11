#ifndef SECURE_TRANSFER_H
#define SECURE_TRANSFER_H

#include <string>

// Encrypt all files in a folder
void encrypt_folder(
    const std::string& input_folder,
    const std::string& output_folder
);

// Decrypt all files in a folder
void decrypt_folder(
    const std::string& input_folder,
    const std::string& output_folder
);

#endif