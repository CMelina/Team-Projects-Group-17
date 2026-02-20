#include "secure_transfer.h"

#include <cstdint>
#include "crypto.h"
#include <fstream>
#include <iostream>
#include <vector>
#include <sys/stat.h>

// read file into byte vector with better diagnostics
static std::vector<unsigned char> read_file(const std::string& path){
    std::cout << "Attempting to read file: " << path << std::endl;

    // Check if file exists first
    struct stat buffer;
    if (stat(path.c_str(), &buffer) != 0) {
        std::cout << "ERROR: File does not exist!" << std::endl;
        return std::vector<unsigned char>();
    }

    std::cout << "File exists. Size according to stat: " << buffer.st_size << " bytes" << std::endl;

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        std::cout << "ERROR: Could not open file!" << std::endl;
        return std::vector<unsigned char>();
    }

    // Get file size using tellg
    file.seekg(0, std::ios::end);
    std::streampos size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::cout << "File size reported by tellg: " << size << " bytes" << std::endl;

    std::vector<unsigned char> data(
        (std::istreambuf_iterator<char>(file)),
         std::istreambuf_iterator<char>()
    );

    std::cout << "Bytes actually read: " << data.size() << std::endl;

    if (data.empty()) {
        std::cout << "WARNING: Read 0 bytes from file!" << std::endl;
    }

    return data;
}

// write byte vector to file
static void write_file(const std::string& path,
                       const std::vector<unsigned char>& data){
    std::cout << "Writing " << data.size() << " bytes to: " << path << std::endl;
    std::ofstream file(path, std::ios::binary);
    file.write((char*)data.data(), data.size());
    std::cout << "Write completed" << std::endl;
}

// convert string → 256-bit key
static std::vector<unsigned char> key_from_string(const std::string& s){
    std::vector<unsigned char> key(32,0);
    for(size_t i=0;i<s.size() && i<32;i++)
        key[i]=s[i];
    return key;
}


// ---------------- ENCRYPT ----------------
bool secure_encrypt_file(
    const std::string& input,
    const std::string& output,
    const std::string& keystr
){
    std::cout << "\n--- Starting file encryption ---" << std::endl;
    std::cout << "Input path: " << input << std::endl;
    std::cout << "Output path: " << output << std::endl;

    auto data = read_file(input);
    auto key  = key_from_string(keystr);

    std::cout << "Input file size: " << data.size() << " bytes" << std::endl;

    if (data.empty()) {
        std::cout << "Input file is empty!" << std::endl;
        return false;
    }

    std::vector<unsigned char> iv, cipher, tag;

    if(!aes256gcm_encrypt(data,key,iv,cipher,tag)) {
        std::cout << "Encryption function returned false" << std::endl;
        return false;
    }

    // Debug output to check sizes
    std::cout << "Encryption - IV size: " << iv.size() << std::endl;
    std::cout << "Encryption - Tag size: " << tag.size() << std::endl;
    std::cout << "Encryption - Cipher size: " << cipher.size() << std::endl;

    if (cipher.empty()) {
        std::cout << "ERROR: Ciphertext is empty!" << std::endl;
        return false;
    }

    // store IV + TAG + CIPHERTEXT (simple format)
    std::vector<unsigned char> out;
    out.insert(out.end(), iv.begin(), iv.end());
    out.insert(out.end(), tag.begin(), tag.end());
    out.insert(out.end(), cipher.begin(), cipher.end());

    std::cout << "Output file size being written: " << out.size() << " bytes" << std::endl;

    write_file(output,out);
    std::cout << "--- File encryption completed ---\n" << std::endl;
    return true;
}

// ---------------- DECRYPT ----------------
bool secure_decrypt_file(
    const std::string& input,
    const std::string& output,
    const std::string& keystr
){
    std::cout << "\n--- Starting file decryption ---" << std::endl;
    std::cout << "Input path: " << input << std::endl;
    std::cout << "Output path: " << output << std::endl;

    auto file = read_file(input);

    std::cout << "Encrypted file size: " << file.size() << " bytes" << std::endl;

    // Check minimum size (12 bytes IV + 16 bytes tag = 28 bytes)
    if(file.size() < 28) {
        std::cout << "File too small: " << file.size() << " bytes" << std::endl;
        return false;
    }

    auto key  = key_from_string(keystr);

    std::vector<unsigned char> iv(file.begin(), file.begin()+12);
    std::vector<unsigned char> tag(file.begin()+12, file.begin()+28);
    std::vector<unsigned char> cipher(file.begin()+28, file.end());

    std::cout << "Extracted - IV size: " << iv.size() << std::endl;
    std::cout << "Extracted - Tag size: " << tag.size() << std::endl;
    std::cout << "Extracted - Cipher size: " << cipher.size() << std::endl;

    if (cipher.empty()) {
        std::cout << "ERROR: Extracted ciphertext is empty!" << std::endl;
        return false;
    }

    std::vector<unsigned char> plain;

    if(!aes256gcm_decrypt(cipher,key,iv,tag,plain)) {
        std::cout << "Decryption function returned false" << std::endl;
        return false;
    }

    std::cout << "Decrypted data size: " << plain.size() << " bytes" << std::endl;

    if (plain.empty()) {
        std::cout << "ERROR: Decrypted data is empty!" << std::endl;
        return false;
    }

    write_file(output,plain);
    std::cout << "Restored file size: " << plain.size() << " bytes" << std::endl;
    std::cout << "--- File decryption completed ---\n" << std::endl;
    return true;
}