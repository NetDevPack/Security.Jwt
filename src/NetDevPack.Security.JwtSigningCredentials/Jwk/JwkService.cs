using NetDevPack.Security.JwtSigningCredentials.Interfaces;
using Microsoft.IdentityModel.Tokens;
using System;

namespace NetDevPack.Security.JwtSigningCredentials.Jwk
{
    public class JwkService : IJsonWebKeyService
    {
        private JsonWebKey GenerateRsa()
        {
            var key = CryptoService.CreateRsaSecurityKey();
            return JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
        }
        private JsonWebKey GenerateECDsa(Algorithm algorithm)
        {
            var key = CryptoService.CreateECDsaSecurityKey(algorithm);
            var parameters = key.ECDsa.ExportParameters(true);
            return new JsonWebKey()
            {
                Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve,
                Use = "sig",
                Kid = key.KeyId,
                KeyId = key.KeyId,
                X = Base64UrlEncoder.Encode(parameters.Q.X),
                Y = Base64UrlEncoder.Encode(parameters.Q.Y),
                D = Base64UrlEncoder.Encode(parameters.D),
                Crv = CryptoService.GetCurveType(algorithm),
                Alg = algorithm
            };
        }
        private JsonWebKey GenerateHMAC(Algorithm algorithms)
        {
            var key = CryptoService.CreateHmacSecurityKey(algorithms);
            var jwk = JsonWebKeyConverter.ConvertFromSymmetricSecurityKey(new SymmetricSecurityKey(key.Key));
            jwk.KeyId = CryptoService.CreateUniqueId();
            return jwk;
        }

        private JsonWebKey GenerateAES(Algorithm algorithms)
        {
            var key = CryptoService.CreateAESSecurityKey(algorithms);
            return JsonWebKeyConverter.ConvertFromSymmetricSecurityKey(new SymmetricSecurityKey(key.Key));
        }

        public JsonWebKey Generate(Algorithm algorithm)
        {
            return algorithm.KeyType switch
            {
                KeyType.RSA => GenerateRsa(),
                KeyType.ECDsa => GenerateECDsa(algorithm),
                KeyType.HMAC => GenerateHMAC(algorithm),
                KeyType.AES => GenerateAES(algorithm),
                _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null)
            };
        }

        public SigningCredentials GenerateSigningCredentials(Algorithm algorithm)
        {
            var key = Generate(algorithm);
            return new SigningCredentials(key, algorithm);
        }

        public SigningCredentials GenerateSigningCredentials(SecurityKey key, Algorithm algorithm)
        {
            if (key == null)
                throw new ArgumentException($"{nameof(key)}");
            return new SigningCredentials(key, algorithm);
        }
    }
}
