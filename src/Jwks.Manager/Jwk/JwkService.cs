using Jwks.Manager.Interfaces;
using Microsoft.IdentityModel.Tokens;
using System;

namespace Jwks.Manager.Jwk
{
    public class JwkService : IJsonWebKeyService
    {
        private SecurityKey GenerateRsa()
        {
            var key = CryptoService.CreateRsaSecurityKey();
            return JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
        }
        private SecurityKey GenerateECDsa()
        {
            var key = CryptoService.CreateECDsaSecurityKey();
            // JsonWebKeyConverter do not support ECDsa
            return key;
        }
        private SecurityKey GenerateHMAC(Algorithm algorithms)
        {
            var key = CryptoService.CreateHmacSecurityKey(algorithms);
            var jwk = JsonWebKeyConverter.ConvertFromSymmetricSecurityKey(new SymmetricSecurityKey(key.Key));
            jwk.KeyId = CryptoService.CreateUniqueId();
            return jwk;
        }

        private SecurityKey GenerateAES(Algorithm algorithms)
        {
            var key = CryptoService.CreateAESSecurityKey(algorithms);
            return new SymmetricSecurityKey(key.Key);
            //var jwk = JsonWebKeyConverter.ConvertFromSecurityKey(new SymmetricSecurityKey(key.Key));
            //jwk.KeyId = CryptoService.CreateUniqueId();
            //return jwk;
        }

        public SecurityKey Generate(Algorithm algorithm)
        {
            return algorithm.KeyType switch
            {
                KeyType.RSA => GenerateRsa(),
                KeyType.ECDsa => GenerateECDsa(),
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
