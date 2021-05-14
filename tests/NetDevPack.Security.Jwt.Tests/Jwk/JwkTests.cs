using Bogus;
using FluentAssertions;
using NetDevPack.Security.JwtSigningCredentials.Jwk;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Claims;
using Xunit;

namespace NetDevPack.Security.JwtSigningCredentials.Tests.Jwk
{
    public class JwkTests
    {
        private readonly JwkService _service;

        public JwkTests()
        {
            _service = new JwkService();
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
        public void ShouldGenerateJwk(string algorithm, KeyType keyType)
        {
            var key = _service.Generate(JwsAlgorithm.Create(algorithm, keyType));
            key.KeyId.Should().NotBeNull();
        }

        [Theory]
        [InlineData(SecurityAlgorithms.HmacSha256, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.HmacSha384, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.HmacSha512, KeyType.HMAC)]
        [InlineData(SecurityAlgorithms.RsaSha256, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSha384, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSha512, KeyType.RSA)]
        public void ShouldBeSameJwtWhenDeterministicToken(string algorithm, KeyType keyType)
        {
            IdentityModelEventSource.ShowPII = true;
            var signingCredentials = _service.GenerateSigningCredentials(JwsAlgorithm.Create(algorithm, keyType));
            var handler = new JsonWebTokenHandler();
            var now = DateTime.Now;
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = "me",
                Audience = "you",
                IssuedAt = now,
                NotBefore = now,
                Expires = now.AddMinutes(5),
                Subject = new ClaimsIdentity(GenerateClaim().Generate(5)),
                SigningCredentials = signingCredentials
            };

            var jwt1 = handler.CreateToken(descriptor);
            var jwt2 = handler.CreateToken(descriptor);

            jwt1.Should().Be(jwt2);
        }

        [Theory]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha256, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha384, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha512, KeyType.RSA)]
        [InlineData(SecurityAlgorithms.EcdsaSha256, KeyType.ECDsa)]
        [InlineData(SecurityAlgorithms.EcdsaSha384, KeyType.ECDsa)]
        [InlineData(SecurityAlgorithms.EcdsaSha512, KeyType.ECDsa)]
        public void ShouldNotBeSameJwtWhenProbabilisticToken(string algorithm, KeyType keyType)
        {
            var signingCredentials = _service.GenerateSigningCredentials(JwsAlgorithm.Create(algorithm, keyType));
            var handler = new JsonWebTokenHandler();
            var now = DateTime.Now;
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = "me",
                Audience = "you",
                IssuedAt = now,
                NotBefore = now,
                Expires = now.AddMinutes(5),
                Subject = new ClaimsIdentity(GenerateClaim().Generate(5)),
                SigningCredentials = signingCredentials
            };

            var jwt1 = handler.CreateToken(descriptor);
            var jwt2 = handler.CreateToken(descriptor);

            jwt1.Should().NotBe(jwt2);
        }


        public Faker<Claim> GenerateClaim()
        {
            return new Faker<Claim>().CustomInstantiator(f => new Claim(f.Internet.DomainName(), f.Lorem.Text()));
        }
    }
}
