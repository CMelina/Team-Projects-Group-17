
#include <iostream>
#include <vector>
#include <string>
#include "src/crypto.h"
#include "src/secure_transfer.h"

void print_usage(const char* program_name) {
    std::cout << "\n🔐 SECURE FILE TRANSFER - AES-256-GCM Encryption\n";
    std::cout << "================================================\n\n";
    std::cout << "USAGE:\n";
    std::cout << "  " << program_name << " encrypt <input_file> <output_file> <key>\n";
    std::cout << "  " << program_name << " decrypt <input_file> <output_file> <key>\n";
    std::cout << "  " << program_name << " test\n";
    std::cout << "  " << program_name << " help\n\n";
    std::cout << "EXAMPLES:\n";
    std::cout << "  " << program_name << " encrypt secret.png encrypted.bin mykey123\n";
    std::cout << "  " << program_name << " decrypt encrypted.bin restored.png mykey123\n";
    std::cout << "  " << program_name << " test\n\n";
    std::cout << "NOTES:\n";
    std::cout << "  - Key can be any string (up to 32 characters)\n";
    std::cout << "  - Output files will be created/overwritten\n";
    std::cout << "  - Test mode uses: test.png → encrypted.bin → restored.png\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string command = argv[1];

    // Help command
    if (command == "help" || command == "--help" || command == "-h") {
        print_usage(argv[0]);
        return 0;
    }

    // Test command
    if (command == "test") {
        std::cout << "\n🧪 Running test with default files...\n";
        std::string input_file = "test.png";
        std::string encrypted_file = "encrypted.bin";
        std::string restored_file = "restored.png";
        std::string filekey = "rebel_secret_key";

        std::cout << "   Input: " << input_file << std::endl;
        std::cout << "   Encrypted: " << encrypted_file << std::endl;
        std::cout << "   Restored: " << restored_file << std::endl;
        std::cout << "   Key: " << filekey << "\n" << std::endl;

        // Raw crypto test
        std::vector<unsigned char> plaintext = {'D','E','A','T','H',' ','S','T','A','R'};
        std::vector<unsigned char> key(32, 0x42);
        std::vector<unsigned char> iv, ciphertext, tag, decrypted;

        if (!aes256gcm_encrypt(plaintext, key, iv, ciphertext, tag)) {
            std::cout << "❌ Raw encryption failed\n";
            return 1;
        }

        if (!aes256gcm_decrypt(ciphertext, key, iv, tag, decrypted)) {
            std::cout << "❌ Raw decryption failed\n";
            return 1;
        }
        std::cout << "✅ Raw crypto verified\n";

        // File encryption test
        if(!secure_encrypt_file(input_file, encrypted_file, filekey)){
            std::cout << "❌ File encryption failed\n";
            return 1;
        }

        if(!secure_decrypt_file(encrypted_file, restored_file, filekey)){
            std::cout << "❌ File decryption failed\n";
            return 1;
        }

        std::cout << "\n✅ All tests passed successfully!\n";
        std::cout << "   Original file: " << input_file << std::endl;
        std::cout << "   Restored file: " << restored_file << std::endl;
    }

    // Encrypt command
    else if (command == "encrypt" && argc == 5) {
        std::string input_file = argv[2];
        std::string output_file = argv[3];
        std::string filekey = argv[4];

        std::cout << "\n🔒 Encrypting file...\n";
        std::cout << "   Input: " << input_file << std::endl;
        std::cout << "   Output: " << output_file << std::endl;
        std::cout << "   Key: " << filekey << "\n" << std::endl;

        if(!secure_encrypt_file(input_file, output_file, filekey)){
            std::cout << "❌ Encryption failed\n";
            return 1;
        }
        std::cout << "✅ Encryption successful!\n";
    }

    // Decrypt command
    else if (command == "decrypt" && argc == 5) {
        std::string input_file = argv[2];
        std::string output_file = argv[3];
        std::string filekey = argv[4];

        std::cout << "\n🔓 Decrypting file...\n";
        std::cout << "   Input: " << input_file << std::endl;
        std::cout << "   Output: " << output_file << std::endl;
        std::cout << "   Key: " << filekey << "\n" << std::endl;

        if(!secure_decrypt_file(input_file, output_file, filekey)){
            std::cout << "❌ Decryption failed\n";
            return 1;
        }
        std::cout << "✅ Decryption successful!\n";
    }

    // Invalid command
    else {
        std::cout << "❌ Unknown command or invalid arguments\n";
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
