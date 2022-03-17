namespace NetDevPack.Security.Jwt.Core.Jwa;

/// <summary>
/// Digital Signatures
/// https://datatracker.ietf.org/doc/html/rfc7518#page-6
/// </summary>
public class DigitalSignaturesAlgorithm
{
    public const string EcdsaSha256 = "ES256";
    public const string EcdsaSha384 = "ES384";
    public const string EcdsaSha512 = "ES512";
    public const string HmacSha256 = "HS256";
    public const string HmacSha384 = "HS384";
    public const string HmacSha512 = "HS512";
    public const string None = "none";
    public const string RsaSha256 = "RS256";
    public const string RsaSha384 = "RS384";
    public const string RsaSha512 = "RS512";
    public const string RsaSsaPssSha256 = "PS256";
    public const string RsaSsaPssSha384 = "PS384";
    public const string RsaSsaPssSha512 = "PS512";

    public DigitalSignaturesAlgorithm(string alg)
    {
        Alg = alg;
    }

    public string Alg { get; set; }

    public static implicit operator string(DigitalSignaturesAlgorithm value) => value.Alg;
    public static implicit operator DigitalSignaturesAlgorithm(string value) => new(value);
}