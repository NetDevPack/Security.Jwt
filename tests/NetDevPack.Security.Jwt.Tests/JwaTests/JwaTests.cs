using System;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Core.Jwa;
using Xunit;

namespace NetDevPack.Security.Jwt.Tests.JwaTests
{
    public class JwaTests
    {
        [Theory]
        [InlineData(DigitalSignaturesAlgorithm.HmacSha256, AlgorithmType.HMAC)]
        [InlineData(DigitalSignaturesAlgorithm.HmacSha384, AlgorithmType.HMAC)]
        [InlineData(DigitalSignaturesAlgorithm.HmacSha512, AlgorithmType.HMAC)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha256, AlgorithmType.RSA)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha384, AlgorithmType.RSA)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha512, AlgorithmType.RSA)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha256, AlgorithmType.RSA)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha384, AlgorithmType.RSA)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha512, AlgorithmType.RSA)]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha256, AlgorithmType.ECDsa)]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha384, AlgorithmType.ECDsa)]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha512, AlgorithmType.ECDsa)]
        public void Should_Choose_Valid_KeyType(string algorithm, AlgorithmType algorithmType)
        {
            var key = Algorithm.Create(algorithm);

            key.AlgorithmType.Should().Be(algorithmType);
            key.CryptographyType.Should().Be(CryptographyType.DigitalSignature);
            key.JwtType.Should().Be(JwtType.Jws);
        }

        [Theory]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha256)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha384)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha512)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha256)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha384)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha512)]
        public void Should_KTY_Be_Rsa(string algorithm)
        {
            var key = Algorithm.Create(algorithm);

            key.Kty().Should().Be("RSA");
        }

        [Theory]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha256)]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha384)]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha512)]
        public void Should_KTY_Be_EllipticCurve(string algorithm)
        {
            var key = Algorithm.Create(algorithm);

            key.Kty().Should().Be("EC");
        }

        [Theory]
        [InlineData(DigitalSignaturesAlgorithm.HmacSha256)]
        [InlineData(DigitalSignaturesAlgorithm.HmacSha384)]
        [InlineData(DigitalSignaturesAlgorithm.HmacSha512)]
        public void Should_KTY_Be_octet(string algorithm)
        {
            var key = Algorithm.Create(algorithm);

            key.Kty().Should().Be("oct");
        }

        [Theory]
        [InlineData(AlgorithmType.HMAC, DigitalSignaturesAlgorithm.HmacSha256)]
        [InlineData(AlgorithmType.RSA, DigitalSignaturesAlgorithm.RsaSsaPssSha256)]
        [InlineData(AlgorithmType.ECDsa, DigitalSignaturesAlgorithm.EcdsaSha256)]
        public void Should_Return_Recommended_Algorithm_For_Jws(AlgorithmType algorithmType, string algorithm)
        {
            var key = Algorithm.Create(algorithmType, JwtType.Jws);

            key.Alg.Should().Be(algorithm);
            key.CryptographyType.Should().Be(CryptographyType.DigitalSignature);
        }

        [Fact]
        public void Should_Return_Recommended_Curve_For_ECDsa()
        {
            var key = Algorithm.Create(AlgorithmType.ECDsa, JwtType.Jws);

            key.Curve.Should().Be(JsonWebKeyECTypes.P256);
            key.CryptographyType.Should().Be(CryptographyType.DigitalSignature);
        }

        [Theory]
        [InlineData(AlgorithmType.AES, EncryptionAlgorithmKey.Aes128KW, EncryptionAlgorithmContent.Aes128CbcHmacSha256)]
        [InlineData(AlgorithmType.RSA, EncryptionAlgorithmKey.RsaOAEP, EncryptionAlgorithmContent.Aes128CbcHmacSha256)]
        public void Should_Return_Recommended_Algorithm_For_Jwe(AlgorithmType algorithmType, EncryptionAlgorithmKey algorithm, EncryptionAlgorithmContent enc)
    {   
            var key = Algorithm.Create(algorithmType, JwtType.Jwe);
            key.Alg.Should().Be(algorithm.Alg);
            key.EncryptionAlgorithmContent.Enc.Should().Be(enc.Enc);
            key.CryptographyType.Should().Be(CryptographyType.Encryption);
        }

        [Theory]
        [InlineData(DigitalSignaturesAlgorithm.HmacSha256, EncryptionAlgorithmContent.Aes128Gcm)]
        [InlineData(DigitalSignaturesAlgorithm.HmacSha256, EncryptionAlgorithmContent.Aes128CbcHmacSha256)]
        [InlineData(DigitalSignaturesAlgorithm.HmacSha256, EncryptionAlgorithmContent.Aes192CbcHmacSha384)]
        [InlineData(DigitalSignaturesAlgorithm.HmacSha256, EncryptionAlgorithmContent.Aes192Gcm)]
        [InlineData(DigitalSignaturesAlgorithm.HmacSha256, EncryptionAlgorithmContent.Aes256CbcHmacSha512)]
        [InlineData(DigitalSignaturesAlgorithm.HmacSha256, EncryptionAlgorithmContent.Aes256Gcm)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha256, EncryptionAlgorithmContent.Aes128Gcm)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha256, EncryptionAlgorithmContent.Aes128CbcHmacSha256)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha256, EncryptionAlgorithmContent.Aes192CbcHmacSha384)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha256, EncryptionAlgorithmContent.Aes192Gcm)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha256, EncryptionAlgorithmContent.Aes256CbcHmacSha512)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSha256, EncryptionAlgorithmContent.Aes256Gcm)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha256, EncryptionAlgorithmContent.Aes128Gcm)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha256, EncryptionAlgorithmContent.Aes128CbcHmacSha256)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha256, EncryptionAlgorithmContent.Aes192CbcHmacSha384)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha256, EncryptionAlgorithmContent.Aes192Gcm)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha256, EncryptionAlgorithmContent.Aes256CbcHmacSha512)]
        [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha256, EncryptionAlgorithmContent.Aes256Gcm)]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha256, EncryptionAlgorithmContent.Aes128Gcm)]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha256, EncryptionAlgorithmContent.Aes128CbcHmacSha256)]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha256, EncryptionAlgorithmContent.Aes192CbcHmacSha384)]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha256, EncryptionAlgorithmContent.Aes192Gcm)]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha256, EncryptionAlgorithmContent.Aes256CbcHmacSha512)]
        [InlineData(DigitalSignaturesAlgorithm.EcdsaSha256, EncryptionAlgorithmContent.Aes256Gcm)]
        public void Should_Not_Accept_Encryption_Info_For_Jws(DigitalSignaturesAlgorithm algorithmType, EncryptionAlgorithmContent enc)
        {
            Action act = () => Algorithm.Create(algorithmType).WithContentEncryption(enc);

            act.Should().Throw<InvalidOperationException>();
        }


        [Theory]
        [InlineData(AlgorithmType.ECDsa )]
        [InlineData(AlgorithmType.HMAC)]
        public void Should_Not_Accept_DigitalSignature_For_Jwe(AlgorithmType type)
        {
            Action act = () => Algorithm.Create(type, JwtType.Jwe);

            act.Should().Throw<InvalidOperationException>();
        }

        [Theory]
        [InlineData(AlgorithmType.AES)]
        public void Should_Not_Accept_EncryptionScheme_For_Jws(AlgorithmType type)
        {
            Action act = () => Algorithm.Create(type, JwtType.Jws);

            act.Should().Throw<InvalidOperationException>();
        }
    }
}