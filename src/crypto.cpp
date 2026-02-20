#include "crypto.h"

#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>

/*
 * AES-256-GCM Encryption
 * - Generates a random IV
 * - Encrypts plaintext
 * - Produces an authentication tag
 */

bool aes256gcm_encrypt(
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& key,
    std::vector<unsigned char>& iv,
    std::vector<unsigned char>& ciphertext,
    std::vector<unsigned char>& tag
) {
    std::cout << "CRYPTO: Starting encryption with plaintext size: " << plaintext.size() << std::endl;

    // Create encryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cout << "CRYPTO: Failed to create context" << std::endl;
        return false;
    }

    // 96-bit IV is recommended for GCM
    iv.resize(12);
    if (1 != RAND_bytes(iv.data(), iv.size())) {
        std::cout << "CRYPTO: Failed to generate random IV" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    std::cout << "CRYPTO: Generated IV of size: " << iv.size() << std::endl;

    // For empty plaintext, handle specially
    if (plaintext.empty()) {
        std::cout << "CRYPTO: Empty plaintext" << std::endl;
        ciphertext.clear();
        tag.resize(16);
        RAND_bytes(tag.data(), tag.size());
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }

    // Resize ciphertext to hold encrypted data
    ciphertext.resize(plaintext.size());
    tag.resize(16);  // 128-bit authentication tag

    // Initialize AES-256-GCM
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        std::cout << "CRYPTO: Failed to initialize encryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr)) {
        std::cout << "CRYPTO: Failed to set IV length" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())) {
        std::cout << "CRYPTO: Failed to set key and IV" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len;
    int ciphertext_len = 0;

    std::cout << "CRYPTO: Calling EVP_EncryptUpdate with plaintext size: " << plaintext.size() << std::endl;

    // Encrypt plaintext into ciphertext
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                      plaintext.data(), plaintext.size())) {
        std::cout << "CRYPTO: EVP_EncryptUpdate failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    std::cout << "CRYPTO: EVP_EncryptUpdate wrote: " << len << " bytes" << std::endl;
    ciphertext_len = len;

    // Finalize encryption
    std::cout << "CRYPTO: Calling EVP_EncryptFinal_ex" << std::endl;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        std::cout << "CRYPTO: EVP_EncryptFinal_ex failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    std::cout << "CRYPTO: EVP_EncryptFinal_ex wrote: " << len << " bytes" << std::endl;
    ciphertext_len += len;

    // Resize ciphertext to actual size
    ciphertext.resize(ciphertext_len);
    std::cout << "CRYPTO: Final ciphertext size: " << ciphertext.size() << std::endl;

    // Retrieve authentication tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data())) {
        std::cout << "CRYPTO: Failed to get tag" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    std::cout << "CRYPTO: Tag size: " << tag.size() << std::endl;

    EVP_CIPHER_CTX_free(ctx);
    std::cout << "CRYPTO: Encryption successful" << std::endl;
    return true;
}

/*
 * AES-256-GCM Decryption
 * - Uses the same IV and key
 * - Verifies authentication tag
 * - Fails if data was modified
 */

bool aes256gcm_decrypt(
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& tag,
    std::vector<unsigned char>& plaintext
) {
    std::cout << "CRYPTO: Starting decryption with ciphertext size: " << ciphertext.size() << std::endl;

    // Handle empty ciphertext
    if (ciphertext.empty()) {
        std::cout << "CRYPTO: Empty ciphertext" << std::endl;
        plaintext.clear();
        return true;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cout << "CRYPTO: Failed to create context" << std::endl;
        return false;
    }

    // Resize plaintext to hold decrypted data (maximum possible size)
    plaintext.resize(ciphertext.size());

    // Initialize decryption
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        std::cout << "CRYPTO: Failed to initialize decryption" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr)) {
        std::cout << "CRYPTO: Failed to set IV length" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())) {
        std::cout << "CRYPTO: Failed to set key and IV" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int len;
    int plaintext_len = 0;

    std::cout << "CRYPTO: Calling EVP_DecryptUpdate with ciphertext size: " << ciphertext.size() << std::endl;

    // Decrypt ciphertext
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                      ciphertext.data(), ciphertext.size())) {
        std::cout << "CRYPTO: EVP_DecryptUpdate failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    std::cout << "CRYPTO: EVP_DecryptUpdate wrote: " << len << " bytes" << std::endl;
    plaintext_len = len;

    // Provide authentication tag for verification
    std::cout << "CRYPTO: Setting tag for verification" << std::endl;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(),
                        (void*)tag.data())) {
        std::cout << "CRYPTO: Failed to set tag" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Finalize decryption
    std::cout << "CRYPTO: Calling EVP_DecryptFinal_ex" << std::endl;
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    std::cout << "CRYPTO: EVP_DecryptFinal_ex returned: " << ret << std::endl;

    if (ret > 0) {
        std::cout << "CRYPTO: EVP_DecryptFinal_ex wrote: " << len << " bytes" << std::endl;
        plaintext_len += len;
        plaintext.resize(plaintext_len);
        std::cout << "CRYPTO: Final plaintext size: " << plaintext.size() << std::endl;
    }

    EVP_CIPHER_CTX_free(ctx);
    return ret > 0;
}