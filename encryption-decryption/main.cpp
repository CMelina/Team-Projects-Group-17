#include <iostream>
#include <string>
#include "src/secure_transfer.h"

void print_usage(const char* program_name) {
    std::cout << "\n🔐 SECURE FILE TRANSFER - AES-256-GCM Encryption\n";
    std::cout << "================================================\n\n";
    std::cout << "USAGE:\n";
    std::cout << "  " << program_name << " encrypt <input_folder> <output_folder>\n";
    std::cout << "  " << program_name << " decrypt <input_folder> <output_folder>\n";
    std::cout << "  " << program_name << " test\n";
    std::cout << "  " << program_name << " help\n\n";

    std::cout << "EXAMPLES:\n";
    std::cout << "  " << program_name << " encrypt input encrypted\n";
    std::cout << "  " << program_name << " decrypt encrypted restored\n";
    std::cout << "  " << program_name << " test\n\n";

    std::cout << "NOTES:\n";
    std::cout << "  - Encryption key is generated internally\n";
    std::cout << "  - All files in the folder will be processed\n";
}

int main(int argc, char* argv[]) {

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string command = argv[1];

    if (command == "help" || command == "--help" || command == "-h") {
        print_usage(argv[0]);
        return 0;
    }

    // Test mode
    if (command == "test") {

        std::cout << "\n🧪 Running folder encryption test...\n";

        std::string input_folder = "input";
        std::string encrypted_folder = "encrypted";
        std::string restored_folder = "restored";

        encrypt_folder(input_folder, encrypted_folder);

        std::cout << "✅ Encryption complete\n";

        decrypt_folder(encrypted_folder, restored_folder);

        std::cout << "✅ Decryption complete\n";
        std::cout << "🎉 Test finished successfully\n";
    }

    // Encrypt folder
    else if (command == "encrypt" && argc == 4) {

        std::string input_folder = argv[2];
        std::string output_folder = argv[3];

        std::cout << "\n🔒 Encrypting folder...\n";
        std::cout << "Input: " << input_folder << std::endl;
        std::cout << "Output: " << output_folder << "\n" << std::endl;

        encrypt_folder(input_folder, output_folder);

        std::cout << "✅ Encryption complete\n";
    }

    // Decrypt folder
    else if (command == "decrypt" && argc == 4) {

        std::string input_folder = argv[2];
        std::string output_folder = argv[3];

        std::cout << "\n🔓 Decrypting folder...\n";
        std::cout << "Input: " << input_folder << std::endl;
        std::cout << "Output: " << output_folder << "\n" << std::endl;

        decrypt_folder(input_folder, output_folder);

        std::cout << "✅ Decryption complete\n";
    }

    else {
        std::cout << "❌ Invalid command\n";
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}