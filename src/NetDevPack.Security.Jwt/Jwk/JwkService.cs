using System;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Interfaces;

namespace NetDevPack.Security.Jwt.Jwk
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
            return JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);

        }
        private JsonWebKey GenerateHMAC(Algorithm jwsAlgorithms)
        {
            var key = CryptoService.CreateHmacSecurityKey(jwsAlgorithms);
            var jwk = JsonWebKeyConverter.ConvertFromSymmetricSecurityKey(new SymmetricSecurityKey(key.Key));
            jwk.KeyId = CryptoService.CreateUniqueId();
            return jwk;
        }

        private JsonWebKey GenerateAES(Algorithm jwsAlgorithms)
        {
            var key = CryptoService.CreateAESSecurityKey(jwsAlgorithms);

            var jwk = JsonWebKeyConverter.ConvertFromSymmetricSecurityKey(new SymmetricSecurityKey(key.Key));
            jwk.KeyId = CryptoService.CreateUniqueId();
            return jwk;
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

        public SigningCredentials GenerateSigningCredentials(JwsAlgorithm jwsAlgorithm)
        {
            var key = Generate(jwsAlgorithm);
            return new SigningCredentials(key, jwsAlgorithm);
        }

        public SigningCredentials GenerateSigningCredentials(SecurityKey key, JwsAlgorithm jwsAlgorithm)
        {
            if (key == null)
                throw new ArgumentException($"{nameof(key)}");
            return new SigningCredentials(key, jwsAlgorithm);
        }
    }
}
