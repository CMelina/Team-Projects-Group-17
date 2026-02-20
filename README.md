# Secure File Transfer 🔐

AES-256-GCM file encryption tool for secure file transfer.

## Features
- 🔒 AES-256-GCM encryption
- ✅ Authentication tag verification (tamper detection)
- 📁 Works with any file type
- 🚀 Simple command-line interface

## Building the Project

### Prerequisites
- CMake 3.10+
- OpenSSL development libraries
- C++ compiler with C++11 support

### Build Instructions
```bash
# Clone the repository
git clone <your-repo-url>
cd secure_transfer

# Create build directory and compile
mkdir build
cd build
cmake ..
make
```

## Usage

**Important**: The executable looks for files in your **current working directory**. Use relative or absolute paths as needed.

### Encrypt a file
```bash
# If file is in current directory
./secure_transfer encrypt secret.pdf encrypted.bin mypassword123

# If file is elsewhere (use relative or absolute path)
./secure_transfer encrypt ../documents/secret.pdf encrypted.bin mypassword123
./secure_transfer encrypt /home/user/secret.pdf encrypted.bin mypassword123
```

### Decrypt a file
```bash
./secure_transfer decrypt encrypted.bin restored.pdf mypassword123
```

### Run tests
```bash
# From build directory (make sure test.png is in parent directory)
./secure_transfer test

# Or from project root
./build/secure_transfer test
```

### Get help
```bash
./secure_transfer help
```

## Examples

### Encrypt an image
```bash
# From build directory
./secure_transfer encrypt ../vacation.jpg vacation.enc mysecretkey

# From project root
./build/secure_transfer encrypt vacation.jpg vacation.enc mysecretkey
```

### Decrypt the image
```bash
./secure_transfer decrypt vacation.enc vacation_decoded.jpg mysecretkey
```

## How It Works
1. Generates a random 12-byte IV (Initialization Vector)
2. Encrypts data using AES-256 in GCM mode
3. Creates a 16-byte authentication tag
4. Stores: `[IV (12 bytes)] + [TAG (16 bytes)] + [CIPHERTEXT]`

## File Format
Encrypted files have this structure:
- **Bytes 0-11**: Initialization Vector (IV)
- **Bytes 12-27**: Authentication Tag
- **Bytes 28+**: Encrypted data

## Security Notes
- The encryption key is derived from your password (first 32 bytes)
- Each encryption uses a unique random IV
- GCM mode provides both confidentiality and integrity
- Tampered files will fail decryption automatically
- Always use strong passwords (at least 12 characters recommended)

## Troubleshooting

### "File does not exist!" error
The executable looks for files relative to your current directory:
```bash
# Check where you are
pwd

# List files in current directory
ls -la

# Use correct path to your file
./secure_transfer encrypt /full/path/to/your/file.jpg output.bin mykey
```

### Permission denied
```bash
chmod +x secure_transfer
```

## License
Free to use, modify, and distribute.