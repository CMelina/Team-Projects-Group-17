#ifndef CRYPTO_H
#define CRYPTO_H

#include <vector>

/*
 * Encrypts data using AES-256-GCM.
 *
 * plaintext  -> raw data to protect (image bytes later)
 * key        -> 256-bit shared secret
 * iv         -> random initialization vector (generated inside)
 * ciphertext -> encrypted output
 * tag        -> authentication tag used for integrity verification
 *
 * Returns true if encryption succeeds.
 */
bool aes256gcm_encrypt(
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& key,
    std::vector<unsigned char>& iv,
    std::vector<unsigned char>& ciphertext,
    std::vector<unsigned char>& tag
);

/*
 * Decrypts AES-256-GCM encrypted data.
 *
 * ciphertext -> encrypted data
 * key        -> same shared key used for encryption
 * iv         -> initialization vector used during encryption
 * tag        -> authentication tag (detects tampering)
 * plaintext  -> recovered original data
 *
 * Returns false if integrity check fails.
 */
bool aes256gcm_decrypt(
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& tag,
    std::vector<unsigned char>& plaintext
);

#endif

