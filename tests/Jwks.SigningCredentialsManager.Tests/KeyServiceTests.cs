using FluentAssertions;
using Jwks.SigningCredentialsManager.Store;
using Jwks.SigningCredentialsManager.Store.FileSystem;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using System.Collections.Generic;
using System.IO;
using Xunit;

namespace Jwks.SigningCredentialsManager.Tests
{
    public class KeyServiceTests
    {
        private readonly KeyService _keyService;
        private readonly IKeyStore _store;
        private readonly Mock<IOptions<JwksOptions>> _options;

        public KeyServiceTests()
        {
            _options = new Mock<IOptions<JwksOptions>>();
            _store = new FileSystemStore(new DirectoryInfo(Path.Combine(Directory.GetCurrentDirectory(), "/KeyServiceTests")), _options.Object);
            _keyService = new KeyService(_store, _options.Object);
        }

        [Fact]
        public void ShouldGenerateDefaultSigning()
        {
            _options.Setup(s => s.Value).Returns(new JwksOptions());
            var sign = _keyService.Generate();
            var current = _keyService.GetCurrent();
            current.Kid.Should().Be(sign.Kid);
        }

        [Fact]
        public void ShouldGenerateFiveDefaultSigning()
        {
            _options.Setup(s => s.Value).Returns(new JwksOptions());
            _store.Clear();
            var keysGenerated = new List<SigningCredentials>();
            for (int i = 0; i < 5; i++)
            {
                var sign = _keyService.Generate();
                keysGenerated.Add(sign);
            }

            var current = _keyService.GetLastKeysCredentials(5);
            foreach (var securityKey in current)
            {
                keysGenerated.Should().Contain(s => s.Kid == securityKey.KeyId);
            }
        }
        [Fact]
        public void ShouldGenerateRsa()
        {
            _options.Setup(s => s.Value).Returns(new JwksOptions());
            var sign = _keyService.Generate();
            var current = _store.GetCurrentKey();
            current.KeyId.Should().Be(sign.Kid);
        }

        [Fact]
        public void ShouldGenerateFiveRsa()
        {
            _store.Clear();
            _options.Setup(s => s.Value).Returns(new JwksOptions() { Algorithm = SecurityAlgorithms.RsaSha256 });

            var keysGenerated = new List<SigningCredentials>();
            for (int i = 0; i < 5; i++)
            {
                var sign = _keyService.Generate();
                keysGenerated.Add(sign);
            }

            var current = _store.Get(10);
            foreach (var securityKey in current)
            {
                keysGenerated.Should().Contain(s => s.Kid == securityKey.KeyId && s.Algorithm == SecurityAlgorithms.RsaSha256);
            }
        }


        [Fact]
        public void ShouldGenerateECDsa()
        {
            _options.Setup(s => s.Value).Returns(new JwksOptions() { Algorithm = SecurityAlgorithms.EcdsaSha256, Format = KeyFormat.ECDsa });
            var sign = _keyService.Generate();
            var current = _store.GetCurrentKey();
            current.KeyId.Should().Be(sign.Kid);
            current.Algorithm.Should().Be(SecurityAlgorithms.EcdsaSha256);
        }

        [Fact]
        public void ShouldGenerateFiveCEDsa()
        {
            _options.Setup(s => s.Value).Returns(new JwksOptions() { Algorithm = SecurityAlgorithms.EcdsaSha512, Format = KeyFormat.ECDsa });
            _store.Clear();
            var keysGenerated = new List<SigningCredentials>();
            for (int i = 0; i < 5; i++)
            {
                var sign = _keyService.Generate();
                keysGenerated.Add(sign);
            }

            var current = _store.Get(50);
            foreach (var securityKey in current)
            {
                keysGenerated.Should().Contain(s => s.Kid == securityKey.KeyId && s.Algorithm == SecurityAlgorithms.EcdsaSha512);
            }
        }
    }
}
