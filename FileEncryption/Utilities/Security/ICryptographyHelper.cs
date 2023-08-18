using FileEncryption.Models;

namespace FileEncryption.Utilities.Security;

public interface ICryptographyHelper
{
    SecurityKey GenerateKey();

    byte[] SignatureFile(string filePath, string privateKey);

    string CalculateFileHash(string filePath);
    
    bool VerifyFileIntegrity(string filePath, string expectedHash);
    bool VerifyFile(string filePath, byte[] signature, string publicKey);

    void EncryptFile(string filePath, string publicKey);
    void EncryptFolder(string folderPath, string publicKey);
    
    void DecryptFile(string filePath, string privateKey);
    void DecryptFolder(string folderPath, string privateKey);
}