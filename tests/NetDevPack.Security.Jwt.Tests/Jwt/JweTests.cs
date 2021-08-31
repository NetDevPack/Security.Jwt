using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using Bogus;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Moq;
using NetDevPack.Security.Jwt.DefaultStore.Memory;
using NetDevPack.Security.Jwt.Interfaces;
using NetDevPack.Security.Jwt.Jwk;
using NetDevPack.Security.Jwt.Jwks;
using NetDevPack.Security.Jwt.Tests.Jwks;
using Xunit;

namespace NetDevPack.Security.Jwt.Tests.Jwt
{
    public class JweTests
    {
        private readonly JwkService _service;
        private readonly JwksService _jwksService;
        private readonly IJsonWebKeyStore _store;
        private readonly Mock<IOptions<JwksOptions>> _options;

        public JweTests()
        {
            _options = new Mock<IOptions<JwksOptions>>();
            _store = new InMemoryStore(_options.Object);
            _jwksService = new JwksService(_store, new JwkService(), _options.Object);
            _options.Setup(s => s.Value).Returns(new JwksOptions());
            _service = new JwkService();
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
        public void ShouldValidateJwe(string algorithm, KeyType keyType, string encryption)
        {
            var options = new JwksOptions()
            {
                KeyPrefix = $"{nameof(JsonWebKeySetServiceTests)}_",
                Jwe = JweAlgorithm.Create(algorithm, keyType).WithEncryption(encryption)
            };

            var encryptingCredentials = _jwksService.GenerateEncryptingCredentials(options);

            var handler = new JsonWebTokenHandler();
            var now = DateTime.Now;
            var jwt = new SecurityTokenDescriptor
            {
                Issuer = "me",
                Audience = "you",
                IssuedAt = now,
                NotBefore = now,
                Expires = now.AddMinutes(5),
                Subject = new ClaimsIdentity(GenerateClaim().Generate(5)),
                EncryptingCredentials = encryptingCredentials
            };

            var jwe = handler.CreateToken(jwt);
            var result = handler.ValidateToken(jwe,
                new TokenValidationParameters
                {
                    ValidIssuer = "me",
                    ValidAudience = "you",
                    RequireSignedTokens = false,
                    TokenDecryptionKey = encryptingCredentials.Key
                });

            result.IsValid.Should().BeTrue();
        }

        [Fact]
        public void ShouldGenerateDefaultEncryption()
        {
            _options.Setup(s => s.Value).Returns(new JwksOptions() { KeyPrefix = $"{nameof(JsonWebKeySetServiceTests)}_" });
            var sign = _jwksService.GenerateEncryptingCredentials();
            var current = _jwksService.GetCurrentEncryptingCredentials();
            current.Key.KeyId.Should().Be(sign.Key.KeyId);
        }



        public Faker<Claim> GenerateClaim()
        {
            return new Faker<Claim>().CustomInstantiator(f => new Claim(f.Internet.DomainName(), f.Lorem.Text()));
        }
    }
}
