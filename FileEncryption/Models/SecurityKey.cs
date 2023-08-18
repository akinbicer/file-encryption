namespace FileEncryption.Models;

public class SecurityKey
{
    public Guid Id { get; set; }
    public DateTime CreatedDate { get; set; }
    public required string PublicKey { get; set; }
    public required string PrivateKey { get; set; }
}