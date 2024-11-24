# Encrypt-Decrypt-Video

This project provides a Python-based utility to encrypt and decrypt video files (or any binary file) using the AES encryption standard. The encryption key is derived from a password using PBKDF2 (Password-Based Key Derivation Function 2) and a randomly generated salt.

## Features

- **Encryption and Decryption:** Securely encrypt and decrypt video files using AES in CBC mode.
- **Password-Based Key Derivation:** Uses PBKDF2 for generating strong keys from a password and salt.
- **Salt Management:** Randomly generates and stores a unique salt for each encryption process.
- **Base64 Encoding:** Handles IV and ciphertext as Base64-encoded strings for storage.

## Project Information

This project is part of the **ENGCE110 Computer and Data Security** course at **Rajamangala University of Technology Lanna**. It serves as a practical implementation project for understanding encryption techniques and secure data handling taught in the course.

## Prerequisites

Before using the script, ensure you have the following installed:

- Python 3.6+
- The `pycryptodome` library:

```bash
pip install pycryptodome
```

## How It Works

1. **Encryption:**

- Reads the input file and pads it to match the AES block size.
- Encrypts the file using a key derived from the password and salt.
- Stores the initialization vector (IV) and ciphertext in a Base64-encoded file.

2. **Decryption:**

- Reads the Base64-encoded IV and ciphertext.
- Uses the same password and salt to derive the key.
- Decrypts and removes padding to reconstruct the original file.

## Usage

### Command-Line Interface

The script can be used via the command line with the following syntax:

```bash
python encrypt_decrypt.py <encrypt|decrypt> <file> <password>
```

### Example

1. **Encrypt a Video:**

```bash
python encrypt_decrypt.py encrypt my_video.mp4 mypassword123
```

Output:

- Encrypted file: `my_video.encrypted`
- Salt saved in `salt.txt`.

2. **Decrypt a Video:**

```bash
python encrypt_decrypt.py decrypt my_video.encrypted mypassword123
```

Output:

- Decrypted file: `my_video_decrypted.mp4`.

## File Descriptions

- `salt.txt`: Stores the generated salt for key derivation.
- **Input File:** The file you want to encrypt or decrypt.
- **Output File:** The resulting encrypted or decrypted file.

## Important Notes

1. **Password Sensitivity:**

- Use strong and memorable passwords.
- The same password and `salt.txt` must be used for decryption.

2. Salt Management:

- Ensure `salt.txt` is not lost; it is required for decryption.
- Do not reuse salts across different files for security reasons.

3. Error Handling:

- If the script encounters incorrect passwords or missing salt, it will raise errors.

## Limitations

- The encrypted output is not human-readable and should not be modified manually.
- Currently supports only AES with CBC mode.
