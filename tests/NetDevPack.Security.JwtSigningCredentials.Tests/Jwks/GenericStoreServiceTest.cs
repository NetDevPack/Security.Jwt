using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Bogus;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.JwtSigningCredentials.Interfaces;
using NetDevPack.Security.JwtSigningCredentials.Jwk;
using NetDevPack.Security.JwtSigningCredentials.Tests.Warmups;
using Xunit;
using Xunit.Abstractions;

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
        }

        [Fact]
        public void ShouldSaveCrypto()
        {
            _keyService.GetCurrent();

            _keyService.GetLastKeysCredentials(5).Count.Should().BePositive();
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
            _keyService.Generate(new JwksOptions()
            { KeyPrefix = "ShouldGenerateManyRsa_", Algorithm = Algorithm.Create(algorithm, keyType) });
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
            var alg = Algorithm.Create(algorithm, keyType);
            var key = _keyService.Generate(new JwksOptions() { KeyPrefix = "ShouldGenerateManyRsa_", Algorithm = alg });
            var privateKey = new SecurityKeyWithPrivate();
            privateKey.SetParameters(key.Key, alg);
            _jsonWebKeyStore.Save(privateKey);

            /*Remove private*/
            privateKey.SetParameters();
            _jsonWebKeyStore.Update(privateKey);

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
            var alg = Algorithm.Create(algorithm, keyType);
            var key = _keyService.Generate(new JwksOptions() { KeyPrefix = "ShouldGenerateManyRsa_", Algorithm = alg });
            var privateKey = new SecurityKeyWithPrivate();
            privateKey.SetParameters(key.Key, alg);
            _jsonWebKeyStore.Save(privateKey);
            /*Remove private*/
            privateKey.SetParameters();
            _jsonWebKeyStore.Update(privateKey);

            var jsonWebKey = _keyService.GetLastKeysCredentials(5).First(w => w.Kid == privateKey.KeyId);
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
            var alg = Algorithm.Create(algorithm, keyType);
            var key = _keyService.Generate(new JwksOptions() { KeyPrefix = "ShouldGenerateManyRsa_", Algorithm = alg });
            var privateKey = new SecurityKeyWithPrivate();
            privateKey.SetParameters(key.Key, alg);
            _jsonWebKeyStore.Save(privateKey);
            
            /*Remove private*/
            privateKey.SetParameters();
            _jsonWebKeyStore.Update(privateKey);

            var jsonWebKey = _keyService.GetLastKeysCredentials(5).First(w => w.Kid == privateKey.KeyId);
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

            var options = new JwksOptions() { Algorithm = Algorithm.Create(algorithm, keyType) };
            var newKey = _keyService.GetCurrent(options);

            _keyService.GetLastKeysCredentials(5).Count.Should().BePositive();

            var currentKey = _keyService.GetCurrent(options);
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

            var options = new JwksOptions() { Algorithm = Algorithm.Create(algorithm, keyType) };

            var handler = new JsonWebTokenHandler();
            var now = DateTime.Now;

            // Generate right now and in memory
            var newKey = _keyService.GetCurrent(options);

            // recovered from database
            var currentKey = _keyService.GetCurrent(options);

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
            var options = new JwksOptions() { Algorithm = Algorithm.Create(algorithm, keyType) };

            var handler = new JsonWebTokenHandler();
            var now = DateTime.Now;

            // Generate right now and in memory
            var newKey = _keyService.GetCurrent(options);

            // recovered from database
            var currentKey = _keyService.GetCurrent(options);

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


        public Faker<Claim> GenerateClaim()
        {
            return new Faker<Claim>().CustomInstantiator(f => new Claim(f.Internet.DomainName(), f.Lorem.Text()));
        }
    }
}
