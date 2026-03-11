#include "secure_transfer.h"
#include "crypto.h"

#include <filesystem>
#include <fstream>
#include <vector>

namespace fs = std::filesystem;

// Read file as bytes
static std::vector<unsigned char> read_file(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);

    return std::vector<unsigned char>(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
}

// Write bytes to file
static void write_file(const std::string& path,
                       const std::vector<unsigned char>& data)
{
    std::ofstream file(path, std::ios::binary);
    file.write((char*)data.data(), data.size());
}

void encrypt_folder(
    const std::string& input_folder,
    const std::string& output_folder
)
{
    auto key = generate_random_key();

    for (const auto& entry : fs::directory_iterator(input_folder))
    {
        auto plaintext = read_file(entry.path().string());

        std::vector<unsigned char> iv, ciphertext, tag;

        aes256gcm_encrypt(plaintext, key, iv, ciphertext, tag);

        std::vector<unsigned char> output;

        output.insert(output.end(), key.begin(), key.end());
        output.insert(output.end(), iv.begin(), iv.end());
        output.insert(output.end(), tag.begin(), tag.end());
        output.insert(output.end(), ciphertext.begin(), ciphertext.end());

        std::string out_file =
            output_folder + "/" + entry.path().filename().string() + ".enc";

        write_file(out_file, output);
    }
}

void decrypt_folder(
    const std::string& input_folder,
    const std::string& output_folder
)
{
    for (const auto& entry : fs::directory_iterator(input_folder))
    {
        auto file = read_file(entry.path().string());

        std::vector<unsigned char> key(file.begin(), file.begin() + 32);
        std::vector<unsigned char> iv(file.begin() + 32, file.begin() + 44);
        std::vector<unsigned char> tag(file.begin() + 44, file.begin() + 60);
        std::vector<unsigned char> ciphertext(file.begin() + 60, file.end());

        std::vector<unsigned char> plaintext;

        aes256gcm_decrypt(ciphertext, key, iv, tag, plaintext);

        std::string out_file =
            output_folder + "/" +
                entry.path().stem().string();

        write_file(out_file, plaintext);
    }
}