using System.Security.Cryptography;
using System.Text;
using FileEncryption.Models;

namespace FileEncryption.Utilities.Security;

public class CryptographyHelper : ICryptographyHelper
{
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

    public string CalculateFileHash(string filePath)
    {
        using var sha256 = SHA256.Create();
        using var stream = File.OpenRead(filePath);

        var hashBytes = sha256.ComputeHash(stream);
        return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
    }

    public byte[] SignatureFile(string filePath, string privateKey)
    {
        using var rsa = RSA.Create();
        rsa.FromXmlString(privateKey);

        var data = File.ReadAllBytes(filePath);
        var signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return signature;
    }

    public bool VerifyFile(string filePath, byte[] signature, string publicKey)
    {
        using var rsa = RSA.Create();
        rsa.FromXmlString(publicKey);

        var data = File.ReadAllBytes(filePath);
        var isValid = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return isValid;
    }

    public bool VerifyFileIntegrity(string filePath, string expectedHash)
    {
        var actualHash = CalculateFileHash(filePath);
        return string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase);
    }

    public void EncryptFile(string filePath, string publicKey)
    {
        var encryptedBytes = Encrypt(File.ReadAllBytes(filePath), publicKey);
        File.WriteAllBytes(filePath, encryptedBytes);
        File.Move(filePath, $"{filePath}.encrypted");
    }

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

    public void DecryptFile(string filePath, string privateKey)
    {
        var decryptedBytes = Decrypt(File.ReadAllBytes(filePath), privateKey);
        File.WriteAllBytes(filePath.Replace(".encrypted", ""), decryptedBytes);
        File.Delete(filePath);
    }

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