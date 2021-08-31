using System;
using System.Security.Claims;
using Bogus;
using FluentAssertions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Jwk;
using Xunit;

namespace NetDevPack.Security.Jwt.Tests.Jwk
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
        public void ShouldGenerateJwkForJws(string algorithm, KeyType keyType)
        {
            var key = _service.Generate(JwsAlgorithm.Create(algorithm, keyType));
            key.KeyId.Should().NotBeNull();
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
        public void ShouldGenerateJwkForJwe(string algorithm, KeyType keyType, string encryption)
        {
            var key = _service.Generate(JweAlgorithm.Create(algorithm, keyType).WithEncryption(encryption));
            key.KeyId.Should().NotBeNull();
        }
        
    }
}
