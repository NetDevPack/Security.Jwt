using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NetDevPack.Security.Jwt.Core.Interfaces;
using NetDevPack.Security.Jwt.Core.Jwa;
using NetDevPack.Security.Jwt.Core.Model;
using NetDevPack.Security.Jwt.Tests.Warmups;
using Xunit;

namespace NetDevPack.Security.Jwt.Tests.ServicesTest
{
    public class SecurityKeyServiceTest
    {
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
        public void Should_Generate_Key_For_Jws(string algorithm)
        {
            var key = new CryptographicKey(Algorithm.Create(algorithm));
            key.Key.KeyId.Should().NotBeNull();
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
        [InlineData(EncryptionAlgorithmKey.RsaOAEP, EncryptionAlgorithmContent.Aes128Gcm)]
        [InlineData(EncryptionAlgorithmKey.RsaPKCS1, EncryptionAlgorithmContent.Aes128Gcm)]
        [InlineData(EncryptionAlgorithmKey.Aes128KW, EncryptionAlgorithmContent.Aes128Gcm)]
        [InlineData(EncryptionAlgorithmKey.Aes256KW, EncryptionAlgorithmContent.Aes128Gcm)]
        [InlineData(EncryptionAlgorithmKey.RsaOAEP, EncryptionAlgorithmContent.Aes256Gcm)]
        [InlineData(EncryptionAlgorithmKey.RsaPKCS1, EncryptionAlgorithmContent.Aes256Gcm)]
        [InlineData(EncryptionAlgorithmKey.Aes128KW, EncryptionAlgorithmContent.Aes256Gcm)]
        [InlineData(EncryptionAlgorithmKey.Aes256KW, EncryptionAlgorithmContent.Aes256Gcm)]
        public void Should_Generate_Key_For_Jwe(string algorithm, string encryption)
        {
            var key = new CryptographicKey(Algorithm.Create(algorithm).WithContentEncryption(encryption));
            key.Key.KeyId.Should().NotBeNull();
        }


        [Theory]
        [InlineData(JwtType.Jwe, AlgorithmType.AES)]
        [InlineData(JwtType.Jwe, AlgorithmType.RSA)]
        [InlineData(JwtType.Jws, AlgorithmType.HMAC)]
        [InlineData(JwtType.Jws, AlgorithmType.RSA)]
        [InlineData(JwtType.Jws, AlgorithmType.ECDsa)]
        public void Should_Generate_Key_For_Recommended_Alg(JwtType jwtType, AlgorithmType type)
        {
            var key = new CryptographicKey(Algorithm.Create(type, jwtType));
            key.Key.KeyId.Should().NotBeNull();
        }
    }
}
