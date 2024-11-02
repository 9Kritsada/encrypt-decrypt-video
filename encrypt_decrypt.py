from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import os
import time

# Function to derive a key from a password using PBKDF2
def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=32)

# Function to generate a random salt and save it to salt.txt
def generate_salt(file_path):
    salt = get_random_bytes(16)  # 16 bytes salt
    with open(file_path, 'wb') as f:
        f.write(salt)
    return salt

# Function to read the salt from salt.txt
def read_salt(file_path):
    with open(file_path, 'rb') as f:
        salt = f.read()
    if len(salt) != 16:
        raise ValueError("Salt must be 16 bytes long.")
    return salt

# Function to encrypt a file using AES and a key derived from a password
def encrypt_file(file_name, output_file_name, password, salt_file):
    block_size = AES.block_size
    try:
        # Start timing
        start_time = time.time()
        
        salt = read_salt(salt_file)
        key = derive_key(password, salt)
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        with open(file_name, 'rb') as input_file:
            plaintext = input_file.read()
        padded_plaintext = pad(plaintext, block_size)
        

        ciphertext = cipher.encrypt(padded_plaintext)

        iv_base64 = base64.b64encode(iv).decode('utf-8')
        ciphertext_base64 = base64.b64encode(ciphertext).decode('utf-8')

        with open(output_file_name, 'w') as output_file:
            output_file.write(f'{iv_base64}\n')
            output_file.write(ciphertext_base64)

        # Stop timing
        end_time = time.time()

        print(f"Encryption complete. Encrypted file saved as: {output_file_name} :)")
        print(f"Time taken for encryption: {end_time - start_time:.4f} seconds")

    except ValueError as e:
        print(f"Error! -> {e} :(")

# Function to decrypt a file using AES and a key derived from a password
def decrypt_file(encrypted_file_name, output_file_name, password, salt_file):
    block_size = AES.block_size
    try:
        # Start timing
        start_time = time.time()
        
        salt = read_salt(salt_file)
        key = derive_key(password, salt)

        with open(encrypted_file_name, 'r') as f:
            iv_base64 = f.readline().strip()
            ciphertext_base64 = f.readline().strip()

        iv = base64.b64decode(iv_base64)
        ciphertext = base64.b64decode(ciphertext_base64)

        cipher = AES.new(key, AES.MODE_CBC, iv)


        padded_plaintext = cipher.decrypt(ciphertext)


        plaintext = unpad(padded_plaintext, block_size)

        with open(output_file_name, 'wb') as output_file:
            output_file.write(plaintext)
            
        # Stop timing
        end_time = time.time()

        print(f"Decryption complete. Decrypted file saved as: {output_file_name} :)")
        print(f"Time taken for decryption: {end_time - start_time:.4f} seconds")

    except ValueError as e:
        print(f"Error! -> {e} :(")
    
# Example usage from command-line arguments
def main():
    import sys
    if len(sys.argv) < 3:
        print("Usage: python encrypt_decrypt.py <encrypt|decrypt> <file> [password]")
        sys.exit(1)

    action = sys.argv[1]  # 'encrypt' or 'decrypt'
    file_name = sys.argv[2]
    password = sys.argv[3]

    salt_file = "salt.txt"  # File to save the generated salt

    if action == 'encrypt':
        output_file = os.path.splitext(file_name)[0] + '.encrypted'
        # Generate salt and save to salt.txt
        generate_salt(salt_file)
        print(f"Salt generated and saved in {salt_file}")
        # Encrypt the file using the password
        encrypt_file(file_name, output_file, password, salt_file)

    elif action == 'decrypt':
        output_file = os.path.splitext(file_name)[0] + '_decrypted' + '.mp4'
        # Decrypt the file using the password
        decrypt_file(file_name, output_file, password, salt_file)

    else:
        print("Invalid action. Use 'encrypt' or 'decrypt'.")
        sys.exit(1)

if __name__ == "__main__":
    main()
