namespace FileEncryption.Models;

/// <summary>
///     Represents a pair of cryptographic keys, including a public key and a private key.
/// </summary>
public class SecurityKey
{
    /// <summary>
    ///     Gets or sets the unique identifier of the security key.
    /// </summary>
    public Guid Id { get; set; }

    /// <summary>
    ///     Gets or sets the creation date of the security key.
    /// </summary>
    public DateTime CreatedDate { get; set; }

    /// <summary>
    ///     Gets or sets the public key.
    /// </summary>
    public required string PublicKey { get; set; }

    /// <summary>
    ///     Gets or sets the private key.
    /// </summary>
    public required string PrivateKey { get; set; }
}