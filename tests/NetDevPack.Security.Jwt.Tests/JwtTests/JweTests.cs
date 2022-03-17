using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Bogus;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Core.Interfaces;
using NetDevPack.Security.Jwt.Core.Jwa;
using NetDevPack.Security.Jwt.Core.Model;
using NetDevPack.Security.Jwt.Tests.Warmups;
using Xunit;

namespace NetDevPack.Security.Jwt.Tests.JwtTests
{
    public class JweTests : IClassFixture<WarmupInMemoryStore>
    {
        private readonly IJwtService _jwksService;

        public JweTests(WarmupInMemoryStore warmup)
        {
            _jwksService = warmup.Services.GetRequiredService<IJwtService>();
        }



        [Theory]
        [InlineData(EncryptionAlgorithmKey.RsaOAEP, EncryptionAlgorithmContent.Aes128CbcHmacSha256)]
        [InlineData(EncryptionAlgorithmKey.RsaPKCS1, EncryptionAlgorithmContent.Aes128CbcHmacSha256)]
        [InlineData(EncryptionAlgorithmKey.Aes128KW, EncryptionAlgorithmContent.Aes128CbcHmacSha256)]
        [InlineData(EncryptionAlgorithmKey.Aes256KW, EncryptionAlgorithmContent.Aes128CbcHmacSha256)]
        [InlineData(EncryptionAlgorithmKey.RsaOAEP, EncryptionAlgorithmContent.Aes256CbcHmacSha512)]
        [InlineData(EncryptionAlgorithmKey.RsaPKCS1, EncryptionAlgorithmContent.Aes256CbcHmacSha512)]
        [InlineData(EncryptionAlgorithmKey.Aes128KW, EncryptionAlgorithmContent.Aes256CbcHmacSha512)]
        [InlineData(EncryptionAlgorithmKey.Aes256KW, EncryptionAlgorithmContent.Aes256CbcHmacSha512)]
        [InlineData(EncryptionAlgorithmKey.RsaOAEP, EncryptionAlgorithmContent.Aes192CbcHmacSha384)]
        [InlineData(EncryptionAlgorithmKey.RsaPKCS1, EncryptionAlgorithmContent.Aes192CbcHmacSha384)]
        [InlineData(EncryptionAlgorithmKey.Aes128KW, EncryptionAlgorithmContent.Aes192CbcHmacSha384)]
        [InlineData(EncryptionAlgorithmKey.Aes256KW, EncryptionAlgorithmContent.Aes192CbcHmacSha384)]
        public void ShouldValidateJwe(string algorithm, string encryption)
        {
            
            var key = new CryptographicKey(Algorithm.Create(algorithm).WithContentEncryption(encryption));
            var encryptingCredentials = new EncryptingCredentials(key, algorithm, encryption);

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


        public Faker<Claim> GenerateClaim()
        {
            return new Faker<Claim>().CustomInstantiator(f => new Claim(f.Internet.DomainName(), f.Lorem.Text()));
        }
    }
}
