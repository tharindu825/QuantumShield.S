# QuantumShield.S

QuantumShield.S is a secure file encryption and decryption tool designed to protect sensitive data using quantum-resistant cryptographic algorithms. It leverages ChaCha20-Poly1305 for encryption, Argon2id for key derivation, and HMAC for integrity verification. The tool includes a robust license validation system and supports recovery key functionality for secure file recovery in case of password loss.

## Features

- **Quantum-Resistant Encryption**: Uses ChaCha20-Poly1305, a quantum-resistant algorithm for secure file encryption.
- **Password-Based Key Derivation**: Employs Argon2id with configurable parameters for secure key derivation.
- **Integrity Protection**: HMAC-SHA256 ensures file integrity during encryption and decryption.
- **Recovery Key Support**: Allows generation of a recovery key for file recovery without the original password.
- **Secure File Deletion**: Implements 7-pass overwrite for secure deletion of original files.
- **License Validation**: Verifies license files with a public key to ensure authorized usage.
- **Folder-Based Processing**: Encrypts or decrypts all files in a specified folder, with support for nested directories.
- **Nonce Management**: Prevents nonce reuse to ensure cryptographic security.

## Requirements

- Python 3.8 or higher
- Required Python packages:
  - `cryptography` (for ChaCha20-Poly1305 and key serialization)
  - `argon2-cffi` (for Argon2id key derivation)
- A valid license file (`license_QS-20250717073721-96d18271.lic`) provided by the QuantumShield.S team
- Operating system: Windows, macOS, or Linux

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-username/QuantumShield.S.git
   cd QuantumShield.S
   ```

2. **Install Dependencies**:
   Install the required Python packages using pip:
   ```bash
   pip install cryptography argon2-cffi
   ```

3. **Obtain a License File**:
   - Contact the QuantumShield.S team to obtain a valid license file (`license_QS-20250717073721-96d18271.lic`).
   - Place the license file in one of the following locations:
     - Same directory as the script
     - Application's base directory
     - User's home directory
     - Current working directory

## Usage

QuantumShield.S provides two main scripts: `QuantumShield.S.py` for encryption/decryption and `RecoveryS.py` for file recovery using a recovery key.

### QuantumShield.S.py

This script handles file encryption and decryption with password-based security.

1. **Run the Script**:
   ```bash
   python QuantumShield.S.py
   ```

2. **Follow the Prompts**:
   - Select an action: `E` for encryption or `D` for decryption.
   - Enter the folder path containing the files to process.
   - Provide a strong password (minimum 12 characters, including uppercase, lowercase, numbers, and special characters).
   - For encryption, choose whether to generate a recovery key (recommended for file recovery).

3. **Output**:
   - Encrypted files will have a `.qs` extension.
   - Original files are securely deleted with a 7-pass overwrite.
   - A `recovery.key` file is created (and hidden on Windows) if recovery key generation is selected.

### RecoveryS.py

This script allows recovery of encrypted files using the recovery key.

1. **Run the Script**:
   ```bash
   python RecoveryS.py
   ```

2. **Follow the Prompts**:
   - Enter the path to the `recovery.key` file.
   - Specify the folder containing encrypted `.qs` files.

3. **Output**:
   - Files are decrypted and restored to their original names.
   - Encrypted `.qs` files are securely deleted.

## Security Notes

- **Password Strength**: Use a strong password with a mix of uppercase, lowercase, numbers, and special characters to ensure security.
- **Recovery Key**: Store the `recovery.key` file in a secure location. It is critical for recovering files if the password is lost.
- **License File**: Ensure the license file is valid and not expired. Contact the QuantumShield.S team for license issues.
- **Nonce Management**: The tool logs nonces to prevent reuse, enhancing cryptographic security.
- **Secure Deletion**: The 7-pass overwrite provides strong deletion security, but effectiveness may vary on SSDs due to wear-leveling.

## Example

### Encrypting a Folder
```bash
$ python QuantumShield.S.py
QuantumShield Encryption Module (Enhanced Version)
------------------------------------------------
Checking license...
Valid license for: [Your Name]
Expiration: 2026-07-17 07:37 UTC

Choose action [E]ncrypt/[D]ecrypt: E
Folder path: ./sensitive_data
Note: Strong passwords are critical for security. Use a mix of characters.
Enter password: ************
Confirm password: ************
Do you want to generate a recovery key? (y/n): y
Recovery key saved to: ./sensitive_data/recovery.key
Processing encryption for folder: ./sensitive_data
Encrypted: ./sensitive_data/document1.txt
Encrypted: ./sensitive_data/document2.pdf
Encryption completed successfully for all 2 files!
Original files were securely deleted with enhanced 7-pass overwrite.
Press Enter to exit...
```

### Recovering Files
```bash
$ python QuantumShield.S.py
--- QuantumShield File Recovery ---
Enter the path to the recovery.key file: ./sensitive_data/recovery.key
Enter the path to the folder with encrypted files: ./sensitive_data
Starting recovery for folder: ./sensitive_data
Recovered: ./sensitive_data/document1.txt.qs
Recovered: ./sensitive_data/document2.pdf.qs
Recovery completed successfully for all 2 files!
Press Enter to exit...
```

## Contributing

Contributions are welcome! Please submit pull requests or open issues on the [GitHub repository](https://github.com/your-username/QuantumShield.S). Ensure any changes maintain compatibility with the existing cryptographic mechanisms and license validation.

## License

QuantumShield.S is licensed under a proprietary license. A valid license file is required to use the software. Contact the QuantumShield.S team for licensing details.

## Support

For support, contact the QuantumShield.S team or open an issue on the [GitHub repository](https://github.com/your-username/QuantumShield.S).