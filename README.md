# File Encryption and Decryption Guide

This document demonstrates how to encrypt and decrypt files using the `CryptographyHelper` class. The provided code example is written in C# and utilizes RSA encryption for file encryption and decryption operations.

## Requirements

- .NET Core SDK

## Warnings

- The sample code is for educational purposes only. Real-world security scenarios might require additional security measures.
- Handle key management carefully. Take necessary precautions to secure private keys.
- File encryption and decryption operations can impact performance, especially for large files.
- This documentation aims to provide a basic understanding. In real projects, thorough testing and security reviews are essential.

## Usage

1. Add or reference the `CryptographyHelper` class to your project.

2. Key Generation:

   ```csharp
   var cryptographyHelper = new CryptographyHelper();
   var key = cryptographyHelper.GenerateKey();
   ```
   In this step, an RSA key pair is generated and converted to a `SecurityKey` object. This key pair will be used for encryption and decryption operations.

3. File Encryption:

   ```csharp
   cryptographyHelper.EncryptFile("path/to/your/file.txt", key.PublicKey);
   ```
   In this step, the specified file at `path/to/your/file.txt` is encrypted using the RSA encryption method.

4. File Decryption:

   ```csharp
   cryptographyHelper.DecryptFile("path/to/your/file.txt.encrypted", key.PrivateKey);
   ```
   In this step, the encrypted file at `path/to/your/file.txt.encrypted` is decrypted using the RSA decryption method.

5. File Signing and Verification:

   ```csharp
   var signature = cryptographyHelper.SignatureFile("path/to/your/file.txt", key.PrivateKey);
   var isValid = cryptographyHelper.VerifyFile("path/to/your/file.txt", signature, key.PublicKey);
   ```
   In these steps, the file is signed and the signature is verified, ensuring the integrity of the file.

6. File Integrity Check:

   ```csharp
   var isIntegrityValid = cryptographyHelper.VerifyFileIntegrity("path/to/your/file.txt", expectedHash);
   ```
   In this step, you can verify the integrity of the file. The `expectedHash` value should contain a precomputed file hash.

7. Folder Encryption and Decryption:

   ```csharp
   cryptographyHelper.EncryptFolder("path/to/your/folder", key.PublicKey);
   cryptographyHelper.DecryptFolder("path/to/your/folder", key.PrivateKey);
   ```
   In these steps, you can encrypt and decrypt all files within the specified folder.

## License
This project is licensed under the MIT License. For more information, see the [LICENSE](LICENSE) file.

## Issues, Feature Requests or Support
Please use the [New Issue](https://github.com/akinbicer/file-encryption/issues/new) button to submit issues, feature requests or support issues directly to me. You can also send an e-mail to akin.bicer@outlook.com.tr.
