using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;

namespace Jwks.SigningCredentialsManager
{
    internal static class CryptoService
    {
        private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();
        /// <summary>
        /// Creates a new RSA security key.
        /// </summary>
        /// <returns></returns>
        internal static RsaSecurityKey CreateRsaSecurityKey(int keySize = 2048)
        {
            return new RsaSecurityKey(RSA.Create(keySize))
            {
                KeyId = CreateUniqueId()
            };
        }

        internal static string CreateUniqueId(int length = 16, OutputFormat format = OutputFormat.Base64Url)
        {
            byte[] randomKey = CreateRandomKey(length);
            return format switch
            {
                OutputFormat.Base64Url => Base64UrlEncoder.Encode(randomKey),
                OutputFormat.Base64 => Convert.ToBase64String(randomKey),
                OutputFormat.Hex => BitConverter.ToString(randomKey).Replace("-", ""),
                _ => throw new ArgumentException("Invalid output format", nameof(format))
            };
        }
        /// <summary>
        /// Creates a new ECDSA security key.
        /// </summary>
        /// <param name="curve">The name of the curve as defined in
        /// https://tools.ietf.org/html/rfc7518#section-6.2.1.1.</param>
        /// <returns></returns>
        internal static ECDsaSecurityKey CreateECDsaSecurityKey(string curve = JsonWebKeyECTypes.P256)
        {
            return new ECDsaSecurityKey(ECDsa.Create(GetCurveFromCrvValue(curve)))
            {
                KeyId = CreateUniqueId()
            };
        }

        /// <summary>
        /// Returns the matching named curve for RFC 7518 crv value
        /// </summary>
        internal static ECCurve GetCurveFromCrvValue(string crv)
        {
            return crv switch
            {
                JsonWebKeyECTypes.P256 => ECCurve.NamedCurves.nistP256,
                JsonWebKeyECTypes.P384 => ECCurve.NamedCurves.nistP384,
                JsonWebKeyECTypes.P521 => ECCurve.NamedCurves.nistP521,
                _ => throw new InvalidOperationException($"Unsupported curve type of {crv}"),
            };
        }


        /// <summary>Creates a random key byte array.</summary>
        /// <param name="length">The length.</param>
        /// <returns></returns>
        internal static byte[] CreateRandomKey(int length)
        {
            byte[] data = new byte[length];
            Rng.GetBytes(data);
            return data;
        }

    }
}