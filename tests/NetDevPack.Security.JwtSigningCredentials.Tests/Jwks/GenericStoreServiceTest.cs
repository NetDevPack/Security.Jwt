using Bogus;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.JwtSigningCredentials.Interfaces;
using NetDevPack.Security.JwtSigningCredentials.Jwk;
using NetDevPack.Security.JwtSigningCredentials.Model;
using NetDevPack.Security.JwtSigningCredentials.Tests.Warmups;
using System;
using System.Linq;
using System.Security.Claims;
using Xunit;

namespace NetDevPack.Security.JwtSigningCredentials.Tests.Jwks
{
    public abstract class GenericStoreServiceTest<TWarmup> : IClassFixture<TWarmup>
        where TWarmup : class, IWarmupTest
    {
        private readonly IJsonWebKeySetService _keyService;
        private readonly IJsonWebKeyStore _jsonWebKeyStore;
        public TWarmup WarmupData { get; }

        public GenericStoreServiceTest(TWarmup warmup)
        {
            WarmupData = warmup;
            _keyService = WarmupData.Services.GetRequiredService<IJsonWebKeySetService>();
            _jsonWebKeyStore = WarmupData.Services.GetRequiredService<IJsonWebKeyStore>();
            this.WarmupData.Clear();
        }

        [Fact]
        public void ShouldSaveCrypto()
        {
            _keyService.GetCurrentSigningCredentials();

            _keyService.GetLastKeysCredentials(JsonWebKeyType.Jws, 5).Count.Should().BePositive();
        }

        [Theory]
        [InlineData(SecurityAlgorithms.HmacSha256, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.HmacSha384, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.HmacSha512, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.RsaSha256, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSha384, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSha512, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha256, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha384, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha512, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.EcdsaSha256, KeyType.ECDsa)]
        [InlineData(SecurityAlgorithms.EcdsaSha384, KeyType.ECDsa)]
        [InlineData(SecurityAlgorithms.EcdsaSha512, KeyType.ECDsa)]
        public void ShouldGenerate(string algorithm, KeyType keyType)
        {
            _keyService.GenerateSigningCredentials(new JwksOptions()
            { KeyPrefix = "ShouldGenerateManyRsa_", Jws = JwsAlgorithm.Create(algorithm, keyType) });
        }

        [Theory]
        [InlineData(SecurityAlgorithms.HmacSha256, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.HmacSha384, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.HmacSha512, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.RsaSha256, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSha384, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSha512, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha256, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha384, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha512, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.EcdsaSha256, KeyType.ECDsa)]
        [InlineData(SecurityAlgorithms.EcdsaSha384, KeyType.ECDsa)]
        [InlineData(SecurityAlgorithms.EcdsaSha512, KeyType.ECDsa)]
        public void ShouldRemovePrivateAndUpdate(string algorithm, KeyType keyType)
        {
            var alg = JwsAlgorithm.Create(algorithm, keyType);
            var key = _keyService.GenerateSigningCredentials(new JwksOptions() { KeyPrefix = "ShouldGenerateManyRsa_", Jws = alg });
            var privateKey = new SecurityKeyWithPrivate();
            privateKey.SetJwsParameters(key.Key, alg);
            _jsonWebKeyStore.Save(privateKey);

            /*Remove private*/
            privateKey.Revoke();
            _jsonWebKeyStore.Revoke(privateKey);

        }



        [Theory]
        [InlineData(SecurityAlgorithms.HmacSha256, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.HmacSha384, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.HmacSha512, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.RsaSha256, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSha384, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSha512, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha256, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha384, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha512, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.EcdsaSha256, KeyType.ECDsa)]
        [InlineData(SecurityAlgorithms.EcdsaSha384, KeyType.ECDsa)]
        [InlineData(SecurityAlgorithms.EcdsaSha512, KeyType.ECDsa)]
        public void ShouldKeepPublicKeyAfterUpdateAExpiredJwk(string algorithm, KeyType keyType)
        {
            var alg = JwsAlgorithm.Create(algorithm, keyType);
            var key = _keyService.GenerateSigningCredentials(new JwksOptions() { KeyPrefix = "ShouldGenerateManyRsa_", Jws = alg });
            var privateKey = new SecurityKeyWithPrivate();
            privateKey.SetJwsParameters(key.Key, alg);
            _jsonWebKeyStore.Save(privateKey);
            /*Remove private*/
            _jsonWebKeyStore.Revoke(privateKey);

            var jsonWebKey = _keyService.GetLastKeysCredentials(JsonWebKeyType.Jws, 5).First(w => w.Kid == privateKey.KeyId);
            jsonWebKey.Kty.Should().NotBeNullOrEmpty();
            jsonWebKey.HasPrivateKey.Should().BeFalse();
            switch (jsonWebKey.Kty)
            {
                case JsonWebAlgorithmsKeyTypes.EllipticCurve:
                    jsonWebKey.X.Should().NotBeNullOrEmpty();
                    jsonWebKey.Y.Should().NotBeNullOrEmpty();
                    break;
                case JsonWebAlgorithmsKeyTypes.RSA:
                    jsonWebKey.N.Should().NotBeNullOrEmpty();
                    jsonWebKey.E.Should().NotBeNullOrEmpty();
                    break;
                case JsonWebAlgorithmsKeyTypes.Octet:
                    jsonWebKey.K.Should().NotBeNullOrEmpty();
                    break;
            }
        }

        [Theory]
        [InlineData(SecurityAlgorithms.HmacSha256, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.HmacSha384, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.HmacSha512, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.RsaSha256, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSha384, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSha512, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha256, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha384, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha512, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.EcdsaSha256, KeyType.ECDsa)]
        [InlineData(SecurityAlgorithms.EcdsaSha384, KeyType.ECDsa)]
        [InlineData(SecurityAlgorithms.EcdsaSha512, KeyType.ECDsa)]
        public void ShouldRemovePrivateKeyAfterUpdateAExpiredJwk(string algorithm, KeyType keyType)
        {
            var alg = JwsAlgorithm.Create(algorithm, keyType);
            var key = _keyService.GenerateSigningCredentials(new JwksOptions() { KeyPrefix = "ShouldGenerateManyRsa_", Jws = alg });
            var privateKey = new SecurityKeyWithPrivate();
            privateKey.SetJwsParameters(key.Key, alg);
            _jsonWebKeyStore.Save(privateKey);

            /*Remove private*/
            privateKey.Revoke();
            _jsonWebKeyStore.Revoke(privateKey);

            var jsonWebKey = _keyService.GetLastKeysCredentials(JsonWebKeyType.Jws, 5).First(w => w.Kid == privateKey.KeyId);
            jsonWebKey.Kty.Should().NotBeNullOrEmpty();
            jsonWebKey.HasPrivateKey.Should().BeFalse();
            switch (jsonWebKey.Kty)
            {
                case JsonWebAlgorithmsKeyTypes.EllipticCurve:
                    jsonWebKey.D.Should().BeNullOrEmpty();
                    break;
                case JsonWebAlgorithmsKeyTypes.RSA:
                    jsonWebKey.D.Should().BeNullOrEmpty();
                    jsonWebKey.DP.Should().BeNullOrEmpty();
                    jsonWebKey.DQ.Should().BeNullOrEmpty();
                    jsonWebKey.P.Should().BeNullOrEmpty();
                    jsonWebKey.Q.Should().BeNullOrEmpty();
                    jsonWebKey.QI.Should().BeNullOrEmpty();
                    break;
                case JsonWebAlgorithmsKeyTypes.Octet:
                    jsonWebKey.K.Should().NotBeNullOrEmpty();
                    break;
            }
        }

        [Theory]
        [InlineData(SecurityAlgorithms.RsaOAEP, KeyType.RSA, SecurityAlgorithms.Aes128CbcHmacSha256)]
        [InlineData(SecurityAlgorithms.RsaPKCS1, KeyType.RSA, SecurityAlgorithms.Aes128CbcHmacSha256)]
        [InlineData(SecurityAlgorithms.Aes128KW, KeyType.AES, SecurityAlgorithms.Aes128CbcHmacSha256)]
        [InlineData(SecurityAlgorithms.Aes256KW, KeyType.AES, SecurityAlgorithms.Aes128CbcHmacSha256)]
        [InlineData(SecurityAlgorithms.RsaOAEP, KeyType.RSA, SecurityAlgorithms.Aes256CbcHmacSha512)]
        [InlineData(SecurityAlgorithms.RsaPKCS1, KeyType.RSA, SecurityAlgorithms.Aes256CbcHmacSha512)]
        [InlineData(SecurityAlgorithms.Aes128KW, KeyType.AES, SecurityAlgorithms.Aes256CbcHmacSha512)]
        [InlineData(SecurityAlgorithms.Aes256KW, KeyType.AES, SecurityAlgorithms.Aes256CbcHmacSha512)]
        [InlineData(SecurityAlgorithms.RsaOAEP, KeyType.RSA, SecurityAlgorithms.Aes192CbcHmacSha384)]
        [InlineData(SecurityAlgorithms.RsaPKCS1, KeyType.RSA, SecurityAlgorithms.Aes192CbcHmacSha384)]
        [InlineData(SecurityAlgorithms.Aes128KW, KeyType.AES, SecurityAlgorithms.Aes192CbcHmacSha384)]
        [InlineData(SecurityAlgorithms.Aes256KW, KeyType.AES, SecurityAlgorithms.Aes192CbcHmacSha384)]
        public void ShouldRemovePrivateKeyFromJweAfterUpdateAExpiredJwk(string algorithm, KeyType keyType, string encryption)
        {
            var alg = JweAlgorithm.Create(algorithm, keyType).WithEncryption(encryption);

            var key = _keyService.GenerateSigningCredentials(new JwksOptions() { KeyPrefix = "ShouldGenerateManyRsa_", Jwe = alg });
            var privateKey = new SecurityKeyWithPrivate();
            privateKey.SetJweParameters(key.Key, alg);
            _jsonWebKeyStore.Save(privateKey);

            /*Remove private*/
            _jsonWebKeyStore.Revoke(privateKey);

            var jsonWebKey = _keyService.GetLastKeysCredentials(JsonWebKeyType.Jwe, 5).First(w => w.Kid == privateKey.KeyId);
            jsonWebKey.Kty.Should().NotBeNullOrEmpty();
            jsonWebKey.HasPrivateKey.Should().BeFalse();
            switch (jsonWebKey.Kty)
            {
                case JsonWebAlgorithmsKeyTypes.EllipticCurve:
                    jsonWebKey.D.Should().BeNullOrEmpty();
                    break;
                case JsonWebAlgorithmsKeyTypes.RSA:
                    jsonWebKey.D.Should().BeNullOrEmpty();
                    jsonWebKey.DP.Should().BeNullOrEmpty();
                    jsonWebKey.DQ.Should().BeNullOrEmpty();
                    jsonWebKey.P.Should().BeNullOrEmpty();
                    jsonWebKey.Q.Should().BeNullOrEmpty();
                    jsonWebKey.QI.Should().BeNullOrEmpty();
                    break;
                case JsonWebAlgorithmsKeyTypes.Octet:
                    jsonWebKey.K.Should().NotBeNullOrEmpty();
                    break;
            }
        }

        [Theory]
        [InlineData(SecurityAlgorithms.HmacSha256, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.HmacSha384, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.HmacSha512, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.RsaSha256, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSha384, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSha512, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha256, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha384, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha512, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.EcdsaSha256, KeyType.ECDsa)]
        [InlineData(SecurityAlgorithms.EcdsaSha384, KeyType.ECDsa)]
        [InlineData(SecurityAlgorithms.EcdsaSha512, KeyType.ECDsa)]
        public void ShouldSaveCryptoAndRecover(string algorithm, KeyType keyType)
        {

            var options = new JwksOptions() { Jws = JwsAlgorithm.Create(algorithm, keyType) };
            var newKey = _keyService.GetCurrentSigningCredentials(options);

            _keyService.GetLastKeysCredentials(JsonWebKeyType.Jws, 5).Count.Should().BePositive();

            var currentKey = _keyService.GetCurrentSigningCredentials(options);
            newKey.Kid.Should().Be(currentKey.Kid);
        }

        [Theory]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha256, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha384, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha512, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.EcdsaSha256, KeyType.ECDsa)]
        [InlineData(SecurityAlgorithms.EcdsaSha384, KeyType.ECDsa)]
        [InlineData(SecurityAlgorithms.EcdsaSha512, KeyType.ECDsa)]
        public void ShouldSaveProbabilisticJwkRecoverAndSigning(string algorithm, KeyType keyType)
        {

            var options = new JwksOptions() { Jws = JwsAlgorithm.Create(algorithm, keyType) };

            var handler = new JsonWebTokenHandler();
            var now = DateTime.Now;

            // Generate right now and in memory
            var newKey = _keyService.GetCurrentSigningCredentials(options);

            // recovered from database
            var currentKey = _keyService.GetCurrentSigningCredentials(options);

            newKey.Kid.Should().Be(currentKey.Kid);
            var claims = new ClaimsIdentity(GenerateClaim().Generate(5));
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = "me",
                Audience = "you",
                IssuedAt = now,
                NotBefore = now,
                Expires = now.AddMinutes(5),
                Subject = claims,
                SigningCredentials = newKey
            };
            var descriptorFromDb = new SecurityTokenDescriptor
            {
                Issuer = "me",
                Audience = "you",
                IssuedAt = now,
                NotBefore = now,
                Expires = now.AddMinutes(5),
                Subject = claims,
                SigningCredentials = currentKey
            };

            var jwt1 = handler.CreateToken(descriptor);
            var jwt2 = handler.CreateToken(descriptorFromDb);

            jwt1.Should().NotBe(jwt2);
        }

        [Theory]
        [InlineData(SecurityAlgorithms.HmacSha256, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.HmacSha384, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.HmacSha512, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.RsaSha256, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSha384, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSha512, KeyType.RSA)]
        public void ShouldSaveDeterministicJwkRecoverAndSigning(string algorithm, KeyType keyType)
        {
            this.WarmupData.Clear();
            var options = new JwksOptions() { Jws = JwsAlgorithm.Create(algorithm, keyType) };

            var handler = new JsonWebTokenHandler();
            var now = DateTime.Now;

            // Generate right now and in memory
            var newKey = _keyService.GetCurrentSigningCredentials(options);

            // recovered from database
            var currentKey = _keyService.GetCurrentSigningCredentials(options);

            newKey.Kid.Should().Be(currentKey.Kid);
            var claims = new ClaimsIdentity(GenerateClaim().Generate(5));
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = "me",
                Audience = "you",
                IssuedAt = now,
                NotBefore = now,
                Expires = now.AddMinutes(5),
                Subject = claims,
                SigningCredentials = newKey
            };
            var descriptorFromDb = new SecurityTokenDescriptor
            {
                Issuer = "me",
                Audience = "you",
                IssuedAt = now,
                NotBefore = now,
                Expires = now.AddMinutes(5),
                Subject = claims,
                SigningCredentials = currentKey
            };

            var jwt1 = handler.CreateToken(descriptor);
            var jwt2 = handler.CreateToken(descriptorFromDb);

            jwt1.Should().Be(jwt2);
        }

        [Theory]
        [InlineData(SecurityAlgorithms.RsaOAEP, KeyType.RSA, SecurityAlgorithms.Aes128CbcHmacSha256)]
        [InlineData(SecurityAlgorithms.RsaPKCS1, KeyType.RSA, SecurityAlgorithms.Aes128CbcHmacSha256)]
        [InlineData(SecurityAlgorithms.Aes128KW, KeyType.AES, SecurityAlgorithms.Aes128CbcHmacSha256)]
        [InlineData(SecurityAlgorithms.Aes256KW, KeyType.AES, SecurityAlgorithms.Aes128CbcHmacSha256)]
        [InlineData(SecurityAlgorithms.RsaOAEP, KeyType.RSA, SecurityAlgorithms.Aes256CbcHmacSha512)]
        [InlineData(SecurityAlgorithms.RsaPKCS1, KeyType.RSA, SecurityAlgorithms.Aes256CbcHmacSha512)]
        [InlineData(SecurityAlgorithms.Aes128KW, KeyType.AES, SecurityAlgorithms.Aes256CbcHmacSha512)]
        [InlineData(SecurityAlgorithms.Aes256KW, KeyType.AES, SecurityAlgorithms.Aes256CbcHmacSha512)]
        [InlineData(SecurityAlgorithms.RsaOAEP, KeyType.RSA, SecurityAlgorithms.Aes192CbcHmacSha384)]
        [InlineData(SecurityAlgorithms.RsaPKCS1, KeyType.RSA, SecurityAlgorithms.Aes192CbcHmacSha384)]
        [InlineData(SecurityAlgorithms.Aes128KW, KeyType.AES, SecurityAlgorithms.Aes192CbcHmacSha384)]
        [InlineData(SecurityAlgorithms.Aes256KW, KeyType.AES, SecurityAlgorithms.Aes192CbcHmacSha384)]
        public void ShouldSaveJweRecoverAndEncrypt(string algorithm, KeyType keyType, string encryption)
        {
            this.WarmupData.Clear();
            var options = new JwksOptions()
            {
                Jwe = JweAlgorithm.Create(algorithm, keyType).WithEncryption(encryption)
            };

            var handler = new JsonWebTokenHandler();
            var now = DateTime.Now;

            // Generate right now and in memory
            var newKey = _keyService.GetCurrentEncryptingCredentials(options);

            // recovered from database
            var currentKey = _keyService.GetCurrentEncryptingCredentials(options);

            newKey.Key.KeyId.Should().Be(currentKey.Key.KeyId);
            var claims = new ClaimsIdentity(GenerateClaim().Generate(5));
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = "me",
                Audience = "you",
                IssuedAt = now,
                NotBefore = now,
                Expires = now.AddMinutes(5),
                Subject = claims,
                EncryptingCredentials = newKey
            };
            var descriptorFromDb = new SecurityTokenDescriptor
            {
                Issuer = "me",
                Audience = "you",
                IssuedAt = now,
                NotBefore = now,
                Expires = now.AddMinutes(5),
                Subject = claims,
                EncryptingCredentials = currentKey
            };

            var jwt1 = handler.CreateToken(descriptor);
            var jwt2 = handler.CreateToken(descriptorFromDb);

            var result = handler.ValidateToken(jwt1,
                new TokenValidationParameters
                {
                    ValidIssuer = "me",
                    ValidAudience = "you",
                    RequireSignedTokens = false,
                    TokenDecryptionKey = currentKey.Key
                });
            result.IsValid.Should().BeTrue();

            result = handler.ValidateToken(jwt2,
               new TokenValidationParameters
               {
                   ValidIssuer = "me",
                   ValidAudience = "you",
                   RequireSignedTokens = false,
                   TokenDecryptionKey = currentKey.Key
               });

            result.IsValid.Should().BeTrue();

        }
        [Fact]
        public void ShouldGenerateAndValidateJweAndJws()
        {
            this.WarmupData.Clear();
            var options = new JwksOptions()
            {
            };

            var handler = new JsonWebTokenHandler();
            var now = DateTime.Now;

            // Generate right now and in memory
            var newKey = _keyService.GetCurrentEncryptingCredentials(options);

            // recovered from database
            var encryptingCredentials = _keyService.GetCurrentEncryptingCredentials(options);
            var signingCredentials = _keyService.GetCurrentSigningCredentials(options);

            var claims = new ClaimsIdentity(GenerateClaim().Generate(5));
            var descriptorJws = new SecurityTokenDescriptor
            {
                Issuer = "me",
                Audience = "you",
                IssuedAt = now,
                NotBefore = now,
                Expires = now.AddMinutes(5),
                Subject = claims,
                SigningCredentials = signingCredentials
            };
            var descriptorJwe = new SecurityTokenDescriptor
            {
                Issuer = "me",
                Audience = "you",
                IssuedAt = now,
                NotBefore = now,
                Expires = now.AddMinutes(5),
                Subject = claims,
                EncryptingCredentials = encryptingCredentials
            };

            var jws = handler.CreateToken(descriptorJws);
            var jwe = handler.CreateToken(descriptorJwe);

            var result = handler.ValidateToken(jws,
                new TokenValidationParameters
                {
                    ValidIssuer = "me",
                    ValidAudience = "you",
                    IssuerSigningKey = signingCredentials.Key
                });
            result.IsValid.Should().BeTrue();

            result = handler.ValidateToken(jwe,
               new TokenValidationParameters
               {
                   ValidIssuer = "me",
                   ValidAudience = "you",
                   RequireSignedTokens = false,
                   TokenDecryptionKey = encryptingCredentials.Key
               });

            result.IsValid.Should().BeTrue();

        }
        public Faker<Claim> GenerateClaim()
        {
            return new Faker<Claim>().CustomInstantiator(f => new Claim(f.Internet.DomainName(), f.Lorem.Text()));
        }
    }
}
