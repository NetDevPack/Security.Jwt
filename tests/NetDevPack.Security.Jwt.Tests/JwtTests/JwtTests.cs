using System;
using System.Security.Claims;
using Bogus;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Core.Interfaces;
using NetDevPack.Security.Jwt.Core.Jwa;
using NetDevPack.Security.Jwt.Core.Model;
using NetDevPack.Security.Jwt.Tests.Warmups;
using Xunit;

namespace NetDevPack.Security.Jwt.Tests.JwtTests
{
    public class JwsTests : IClassFixture<WarmupInMemoryStore>
    {
        private readonly IJwtService _service;

        public JwsTests(WarmupInMemoryStore warmup)
        {
            _service = warmup.Services.GetRequiredService<IJwtService>();
        }

        [Theory]
        [InlineData(DigitalSignaturesAlgorithm.HmacSha256)]
        [InlineData(DigitalSignaturesAlgorithm.HmacSha384)]
        [InlineData(DigitalSignaturesAlgorithm.HmacSha512)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha256)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha384)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha512)]
        public void ShouldBeSameJwtWhenDeterministicToken(string algorithm)
        {
            IdentityModelEventSource.ShowPII = true;
            var signingCredentials = new SigningCredentials(new CryptographicKey(algorithm), algorithm);
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
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha256)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha384)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha512)]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha256)]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha384)]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha512)]
        public void ShouldNotBeSameJwtWhenProbabilisticToken(string algorithm)
        {
            var signingCredentials = new SigningCredentials(new CryptographicKey(algorithm), algorithm);
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
        [InlineData(DigitalSignaturesAlgorithm.HmacSha256)]
        [InlineData(DigitalSignaturesAlgorithm.HmacSha384)]
        [InlineData(DigitalSignaturesAlgorithm.HmacSha512)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha256)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha384)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha512)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha256)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha384)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha512)]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha256)]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha384)]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha512)]
        public void ShouldValidateJws(string algorithm)
        {

            var signingCredentials = new SigningCredentials(new CryptographicKey(algorithm), algorithm);
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
        [InlineData(DigitalSignaturesAlgorithm.HmacSha256)]
        [InlineData(DigitalSignaturesAlgorithm.HmacSha384)]
        [InlineData(DigitalSignaturesAlgorithm.HmacSha512)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha256)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha384)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha512)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha256)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha384)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha512)]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha256)]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha384)]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha512)]
        public void ShouldGetCurrentToSignAndValidateJws(string algorithm)
        {

            var signingCredentials = new SigningCredentials(new CryptographicKey(algorithm), algorithm);
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
