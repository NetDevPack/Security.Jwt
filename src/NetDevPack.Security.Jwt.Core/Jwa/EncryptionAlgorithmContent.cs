using System.Diagnostics;

namespace NetDevPack.Security.Jwt.Core.Jwa;

/// <summary>
/// Encryption algorithms for Content Encryption
/// https://tools.ietf.org/html/rfc7518#section-5.1
/// There are many others at RFC, but dotnet only support some of them.
/// </summary>
[DebuggerDisplay("{Enc}")]
public class EncryptionAlgorithmContent
{
    public EncryptionAlgorithmContent(string enc)
    {
        Enc = enc;
    }

    public const string Aes128CbcHmacSha256 = "A128CBC-HS256";
    public const string Aes192CbcHmacSha384 = "A192CBC-HS384";
    public const string Aes256CbcHmacSha512 = "A256CBC-HS512";
    public const string Aes128Gcm = "A128GCM";
    public const string Aes192Gcm = "A192GCM";
    public const string Aes256Gcm = "A256GCM";
    public string Enc { get; }

    public static implicit operator string(EncryptionAlgorithmContent value) => value.Enc;
    public static implicit operator EncryptionAlgorithmContent(string value) => new(value);
}