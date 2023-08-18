using System.Security.Cryptography;
using FileEncryption.Models;

namespace FileEncryption.Utilities.Security;

/// <summary>
///     Helper class for various cryptography operations, such as key generation, file hashing,
///     signature creation and verification, file encryption, and decryption.
/// </summary>
public class CryptographyHelper : ICryptographyHelper
{
    /// <summary>
    ///     Generates a new RSA key pair.
    /// </summary>
    /// <returns>The generated SecurityKey containing the new key pair.</returns>
    public SecurityKey GenerateKey()
    {
        using var rsa = RSA.Create();
        rsa.KeySize = 2048;

        return new SecurityKey
        {
            Id = Guid.NewGuid(),
            CreatedDate = DateTime.Now,
            PublicKey = rsa.ToXmlString(false),
            PrivateKey = rsa.ToXmlString(true)
        };
    }

    /// <summary>
    ///     Calculates the SHA-256 hash of a file.
    /// </summary>
    /// <param name="filePath">The path of the file to calculate the hash for.</param>
    /// <returns>The calculated SHA-256 hash as a lowercase hexadecimal string.</returns>
    public string CalculateFileHash(string filePath)
    {
        using var sha256 = SHA256.Create();
        using var stream = File.OpenRead(filePath);

        var hashBytes = sha256.ComputeHash(stream);
        return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
    }

    /// <summary>
    ///     Creates a digital signature for a file using the provided private key.
    /// </summary>
    /// <param name="filePath">The path of the file to sign.</param>
    /// <param name="privateKey">The private key to use for signing.</param>
    /// <returns>The digital signature as a byte array.</returns>
    public byte[] SignatureFile(string filePath, string privateKey)
    {
        using var rsa = RSA.Create();
        rsa.FromXmlString(privateKey);

        var data = File.ReadAllBytes(filePath);
        var signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return signature;
    }

    /// <summary>
    ///     Verifies the integrity of a file using its digital signature and the provided public key.
    /// </summary>
    /// <param name="filePath">The path of the file to verify.</param>
    /// <param name="signature">The digital signature to verify against.</param>
    /// <param name="publicKey">The public key to use for verification.</param>
    /// <returns>True if the file's integrity is verified; otherwise, false.</returns>
    public bool VerifyFile(string filePath, byte[] signature, string publicKey)
    {
        using var rsa = RSA.Create();
        rsa.FromXmlString(publicKey);

        var data = File.ReadAllBytes(filePath);
        var isValid = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return isValid;
    }

    /// <summary>
    ///     Verifies the integrity of a file by comparing its calculated hash with an expected hash.
    /// </summary>
    /// <param name="filePath">The path of the file to verify.</param>
    /// <param name="expectedHash">The expected hash value to compare against.</param>
    /// <returns>True if the actual hash matches the expected hash; otherwise, false.</returns>
    public bool VerifyFileIntegrity(string filePath, string expectedHash)
    {
        var actualHash = CalculateFileHash(filePath);
        return string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    ///     Encrypts a file using the provided public key.
    /// </summary>
    /// <param name="filePath">The path of the file to encrypt.</param>
    /// <param name="publicKey">The public key to use for encryption.</param>
    public void EncryptFile(string filePath, string publicKey)
    {
        var encryptedBytes = Encrypt(File.ReadAllBytes(filePath), publicKey);
        File.WriteAllBytes(filePath, encryptedBytes);
        File.Move(filePath, $"{filePath}.encrypted");
    }

    /// <summary>
    ///     Encrypts all files in a folder and its subfolders using the provided public key.
    /// </summary>
    /// <param name="folderPath">The path of the folder to encrypt.</param>
    /// <param name="publicKey">The public key to use for encryption.</param>
    public void EncryptFolder(string folderPath, string publicKey)
    {
        var files = Directory.GetFiles(folderPath, "*.*", SearchOption.AllDirectories);

        foreach (var file in files)
        {
            var encryptedBytes = Encrypt(File.ReadAllBytes(file), publicKey);
            File.WriteAllBytes(file, encryptedBytes);
            File.Move(file, $"{file}.encrypted");
        }
    }

    /// <summary>
    ///     Decrypts an encrypted file using the provided private key.
    /// </summary>
    /// <param name="filePath">The path of the file to decrypt.</param>
    /// <param name="privateKey">The private key to use for decryption.</param>
    public void DecryptFile(string filePath, string privateKey)
    {
        var decryptedBytes = Decrypt(File.ReadAllBytes(filePath), privateKey);
        File.WriteAllBytes(filePath.Replace(".encrypted", ""), decryptedBytes);
        File.Delete(filePath);
    }

    /// <summary>
    ///     Decrypts all encrypted files in a folder and its subfolders using the provided private key.
    /// </summary>
    /// <param name="folderPath">The path of the folder to decrypt.</param>
    /// <param name="privateKey">The private key to use for decryption.</param>
    public void DecryptFolder(string folderPath, string privateKey)
    {
        var files = Directory.GetFiles(folderPath, "*.encrypted", SearchOption.AllDirectories);

        foreach (var file in files)
        {
            var decryptedBytes = Decrypt(File.ReadAllBytes(file), privateKey);
            File.WriteAllBytes(file.Replace(".encrypted", ""), decryptedBytes);
            File.Delete(file);
        }
    }

    private byte[] Encrypt(byte[] bytes, string publicKey)
    {
        using var rsa = RSA.Create();
        rsa.FromXmlString(publicKey);

        return rsa.Encrypt(bytes, RSAEncryptionPadding.OaepSHA256);
    }

    private byte[] Decrypt(byte[] bytes, string privateKey)
    {
        using var rsa = RSA.Create();
        rsa.FromXmlString(privateKey);

        return rsa.Decrypt(bytes, RSAEncryptionPadding.OaepSHA256);
    }
}