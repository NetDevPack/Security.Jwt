using Microsoft.IdentityModel.Tokens;

namespace NetDevPack.Security.Jwt.Core.Jwa;

public class Algorithm
{
    private Algorithm(string algorithm)
    {
        switch (algorithm)
        {
            case EncryptionAlgorithmKey.Aes128KW:
            case EncryptionAlgorithmKey.Aes256KW:
                AlgorithmType = AlgorithmType.AES;
                CryptographyType = CryptographyType.Encryption;
                break;
            case EncryptionAlgorithmKey.RsaPKCS1:
            case EncryptionAlgorithmKey.RsaOAEP:
                CryptographyType = CryptographyType.Encryption;
                AlgorithmType = AlgorithmType.RSA;
                break;
            case DigitalSignaturesAlgorithm.EcdsaSha256:
            case DigitalSignaturesAlgorithm.EcdsaSha384:
            case DigitalSignaturesAlgorithm.EcdsaSha512:
                CryptographyType = CryptographyType.DigitalSignature;
                AlgorithmType = AlgorithmType.ECDsa;
                break;

            case DigitalSignaturesAlgorithm.HmacSha256:
            case DigitalSignaturesAlgorithm.HmacSha384:
            case DigitalSignaturesAlgorithm.HmacSha512:
                CryptographyType = CryptographyType.DigitalSignature;
                AlgorithmType = AlgorithmType.HMAC;
                break;

            case DigitalSignaturesAlgorithm.RsaSha256:
            case DigitalSignaturesAlgorithm.RsaSha384:
            case DigitalSignaturesAlgorithm.RsaSha512:
            case DigitalSignaturesAlgorithm.RsaSsaPssSha256:
            case DigitalSignaturesAlgorithm.RsaSsaPssSha384:
            case DigitalSignaturesAlgorithm.RsaSsaPssSha512:
                CryptographyType = CryptographyType.DigitalSignature;
                AlgorithmType = AlgorithmType.RSA;
                break;
            default:
                throw new NotSupportedException($"Not supported algorithm {algorithm}");
        }

        Alg = algorithm;
    }

    private Algorithm()
    {
        AlgorithmType = AlgorithmType.RSA;
    }

    public EncryptionAlgorithmContent EncryptionAlgorithmContent { get; set; }

    public AlgorithmType AlgorithmType { get; internal set; }
    public CryptographyType CryptographyType { get; internal set; }
    public JwtType JwtType => CryptographyType == CryptographyType.Encryption ? JwtType.Jwe : JwtType.Jws;
    public string Use => CryptographyType == CryptographyType.Encryption ? "enc" : "sig";
    public string Alg { get; internal set; }
    public string Curve { get; set; }


    public Algorithm WithCurve(string curve)
    {
        if (this.AlgorithmType != AlgorithmType.ECDsa)
            throw new InvalidOperationException("Only Elliptic Curves accept curves");

        this.Curve = curve;
        return this;
    }

    /// <summary>
    /// Content encryption algorithm
    /// https://datatracker.ietf.org/doc/html/rfc7518#section-5.1
    /// </summary>
    public Algorithm WithContentEncryption(EncryptionAlgorithmContent enc)
    {
        if (CryptographyType == CryptographyType.DigitalSignature)
            throw new InvalidOperationException("Only Json Web Encryption has enc param");

        switch (enc)
        {
            case Jwa.EncryptionAlgorithmContent.Aes128CbcHmacSha256:
            case Jwa.EncryptionAlgorithmContent.Aes128Gcm:
            case Jwa.EncryptionAlgorithmContent.Aes192CbcHmacSha384:
            case Jwa.EncryptionAlgorithmContent.Aes192Gcm:
            case Jwa.EncryptionAlgorithmContent.Aes256CbcHmacSha512:
            case Jwa.EncryptionAlgorithmContent.Aes256Gcm:
                EncryptionAlgorithmContent = enc;
                break;
            default:
                throw new NotSupportedException($"Not supported encryption algorithm {enc}");
        }

        return this;
    }


    /// <summary>
    /// See RFC 7518 - JSON Web Algorithms (JWA) - Section 6.1. "kty" (Key Type) Parameter Values
    /// </summary>
    public string Kty()
    {
        return AlgorithmType switch
        {
            AlgorithmType.RSA => JsonWebAlgorithmsKeyTypes.RSA,
            AlgorithmType.ECDsa => JsonWebAlgorithmsKeyTypes.EllipticCurve,
            AlgorithmType.HMAC => JsonWebAlgorithmsKeyTypes.Octet,
            AlgorithmType.AES => JsonWebAlgorithmsKeyTypes.Octet,
            _ => throw new ArgumentOutOfRangeException()
        };
    }

    public static Algorithm Create(string algorithm)
    {
        return new Algorithm(algorithm);
    }

    public static Algorithm Create(AlgorithmType algorithmType, JwtType jwtType)
    {
        if (jwtType == JwtType.Both)
            return new Algorithm();

        if (jwtType == JwtType.Jws)
            return algorithmType switch
            {
                AlgorithmType.RSA => new Algorithm(DigitalSignaturesAlgorithm.RsaSsaPssSha256),
                AlgorithmType.ECDsa => new Algorithm(DigitalSignaturesAlgorithm.EcdsaSha256).WithCurve(JsonWebKeyECTypes.P256),
                AlgorithmType.HMAC => new Algorithm(DigitalSignaturesAlgorithm.HmacSha256),
                _ => throw new InvalidOperationException($"Invalid algorithm for Json Web Signature (JWS): {algorithmType}")
            };

        return algorithmType switch
        {
            AlgorithmType.RSA => new Algorithm(EncryptionAlgorithmKey.RsaOAEP).WithContentEncryption(EncryptionAlgorithmContent.Aes128CbcHmacSha256),
            AlgorithmType.AES => new Algorithm(EncryptionAlgorithmKey.Aes128KW).WithContentEncryption(EncryptionAlgorithmContent.Aes128CbcHmacSha256),
            _ => throw new InvalidOperationException($"Invalid algorithm for Json Web Encryption (JWE): {algorithmType}")
        };
    }

    public static implicit operator string(Algorithm value) => value.Alg;
    public static implicit operator Algorithm(string value) => new (value);
}