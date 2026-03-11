# Secure File Transfer 🔐

This project implements a secure file encryption and decryption pipeline using AES-256-GCM with OpenSSL.

The program encrypts every file in a folder before transmission and restores them after reception.

## Features

• AES-256-GCM authenticated encryption

• Automatic key generation

• Folder-level encryption and decryption

• Integrity verification (tamper detection)

• Works on Linux / Raspberry Pi


## Dependencies

Install required packages:

sudo apt update

sudo apt install build-essential cmake libssl-dev

These install:

g++

CMake

OpenSSL crypto library

## Building the Project

From the project root:

mkdir build

cd build

cmake ..

make


This will generate the executable:

## secure_transfer

## Usage

Encrypt a folder

./secure_transfer encrypt <input_folder> <output_folder>

### Example:

./secure_transfer encrypt ../input ../encrypted

Decrypt a folder

./secure_transfer decrypt <encrypted_folder> <output_folder>

### Example:

./secure_transfer decrypt ../encrypted ../decrypted

Encryption Format

Each encrypted file stores the following:

KEY (32 bytes)

IV  (12 bytes)

TAG (16 bytes)

CIPHERTEXT

This allows the receiver to decrypt the file without exposing the key in the command line.


## Security Properties

AES-256-GCM provides:

• Confidentiality – encrypted data cannot be read

• Integrity – tampered files are rejected

• Authentication – ensures correct decryption key


If authentication fails, the file will not decrypt.


