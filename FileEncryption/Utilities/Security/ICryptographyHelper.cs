using FileEncryption.Models;

namespace FileEncryption.Utilities.Security;

/// <summary>
///     Interface for a cryptography helper providing various cryptography operations, such as key generation,
///     file hashing, signature creation and verification, file encryption, and decryption.
/// </summary>
public interface ICryptographyHelper
{
    /// <summary>
    ///     Generates a new RSA key pair.
    /// </summary>
    /// <returns>The generated SecurityKey containing the new key pair.</returns>
    SecurityKey GenerateKey();

    /// <summary>
    ///     Creates a digital signature for a file using the provided private key.
    /// </summary>
    /// <param name="filePath">The path of the file to sign.</param>
    /// <param name="privateKey">The private key to use for signing.</param>
    /// <returns>The digital signature as a byte array.</returns>
    byte[] SignatureFile(string filePath, string privateKey);

    /// <summary>
    ///     Calculates the SHA-256 hash of a file.
    /// </summary>
    /// <param name="filePath">The path of the file to calculate the hash for.</param>
    /// <returns>The calculated SHA-256 hash as a lowercase hexadecimal string.</returns>
    string CalculateFileHash(string filePath);

    /// <summary>
    ///     Verifies the integrity of a file by comparing its calculated hash with an expected hash.
    /// </summary>
    /// <param name="filePath">The path of the file to verify.</param>
    /// <param name="expectedHash">The expected hash value to compare against.</param>
    /// <returns>True if the actual hash matches the expected hash; otherwise, false.</returns>
    bool VerifyFileIntegrity(string filePath, string expectedHash);

    /// <summary>
    ///     Verifies the integrity of a file using its digital signature and the provided public key.
    /// </summary>
    /// <param name="filePath">The path of the file to verify.</param>
    /// <param name="signature">The digital signature to verify against.</param>
    /// <param name="publicKey">The public key to use for verification.</param>
    /// <returns>True if the file's integrity is verified; otherwise, false.</returns>
    bool VerifyFile(string filePath, byte[] signature, string publicKey);

    /// <summary>
    ///     Encrypts a file using the provided public key.
    /// </summary>
    /// <param name="filePath">The path of the file to encrypt.</param>
    /// <param name="publicKey">The public key to use for encryption.</param>
    void EncryptFile(string filePath, string publicKey);

    /// <summary>
    ///     Encrypts all files in a folder and its subfolders using the provided public key.
    /// </summary>
    /// <param name="folderPath">The path of the folder to encrypt.</param>
    /// <param name="publicKey">The public key to use for encryption.</param>
    void EncryptFolder(string folderPath, string publicKey);

    /// <summary>
    ///     Decrypts an encrypted file using the provided private key.
    /// </summary>
    /// <param name="filePath">The path of the file to decrypt.</param>
    /// <param name="privateKey">The private key to use for decryption.</param>
    void DecryptFile(string filePath, string privateKey);

    /// <summary>
    ///     Decrypts all encrypted files in a folder and its subfolders using the provided private key.
    /// </summary>
    /// <param name="folderPath">The path of the folder to decrypt.</param>
    /// <param name="privateKey">The private key to use for decryption.</param>
    void DecryptFolder(string folderPath, string privateKey);
}