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
    public class JwsTests
    {
        private readonly JwkService _service;

        private readonly JwksService _jwksService;
        private readonly IJsonWebKeyStore _store;
        private readonly Mock<IOptions<JwksOptions>> _options;

        public JwsTests()
        {
            _options = new Mock<IOptions<JwksOptions>>();
            _store = new InMemoryStore(_options.Object);
            _jwksService = new JwksService(_store, new JwkService(), _options.Object);
            _options.Setup(s => s.Value).Returns(new JwksOptions());
            _service = new JwkService();
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
        public void ShouldValidateJws(string algorithm, KeyType keyType)
        {
            var options = new JwksOptions()
            {
                Jws = JwsAlgorithm.Create(algorithm, keyType),
                KeyPrefix = $"{nameof(JsonWebKeySetServiceTests)}_"
            };
            var signingCredentials = _jwksService.GenerateSigningCredentials(options);
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
                SigningCredentials = signingCredentials
            };

            var jws = handler.CreateToken(jwt);
            var result = handler.ValidateToken(jws,
                new TokenValidationParameters
                {
                    ValidIssuer = "me",
                    ValidAudience = "you",
                    IssuerSigningKey = signingCredentials.Key
                });

            result.IsValid.Should().BeTrue();
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
        public void ShouldGetCurrentToSignAndValidateJws(string algorithm, KeyType keyType)
        {
            var options = new JwksOptions() { Jws = JwsAlgorithm.Create(algorithm, keyType), KeyPrefix = $"{nameof(JsonWebKeySetServiceTests)}_" };
            _jwksService.GenerateSigningCredentials(options);
            var signingCredentials = _jwksService.GetCurrentSigningCredentials();
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

            var jwt = handler.CreateToken(descriptor);
            var result = handler.ValidateToken(jwt,
                new TokenValidationParameters
                {
                    ValidIssuer = "me",
                    ValidAudience = "you",
                    IssuerSigningKey = signingCredentials.Key
                });

            result.IsValid.Should().BeTrue();
        }



        public Faker<Claim> GenerateClaim()
        {
            return new Faker<Claim>().CustomInstantiator(f => new Claim(f.Internet.DomainName(), f.Lorem.Text()));
        }
    }


}
