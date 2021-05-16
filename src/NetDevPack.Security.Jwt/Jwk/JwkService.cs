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
            return JsonWebKeyConverter.ConvertFromSymmetricSecurityKey(new SymmetricSecurityKey(key.Key));
        }

        public JsonWebKey Generate(Algorithm jwsAlgorithm)
        {
            return jwsAlgorithm.KeyType switch
            {
                KeyType.RSA => GenerateRsa(),
                KeyType.ECDsa => GenerateECDsa(jwsAlgorithm),
                KeyType.HMAC => GenerateHMAC(jwsAlgorithm),
                KeyType.AES => GenerateAES(jwsAlgorithm),
                _ => throw new ArgumentOutOfRangeException(nameof(jwsAlgorithm), jwsAlgorithm, null)
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
