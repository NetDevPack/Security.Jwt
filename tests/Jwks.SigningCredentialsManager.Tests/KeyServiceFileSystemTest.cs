using FluentAssertions;
using Jwks.SigningCredentialsManager.Store;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.Linq;
using Xunit;
using Xunit.Abstractions;

namespace Jwks.SigningCredentialsManager.Tests
{
    public class KeyServiceFileSystemTest : IClassFixture<WarmupFileStore>
    {
        private readonly IKeyService _keyService;
        private ITestOutputHelper _output;
        private IKeyStore _keyStore;
        public WarmupFileStore FileStoreWarmupData { get; }
        public KeyServiceFileSystemTest(WarmupFileStore fileStoreWarmup, ITestOutputHelper output)
        {
            _output = output;
            FileStoreWarmupData = fileStoreWarmup;
            _keyService = FileStoreWarmupData.Services.GetRequiredService<IKeyService>();
            _keyStore = FileStoreWarmupData.Services.GetRequiredService<IKeyStore>();

        }

        [Fact]
        public void ShouldSaveCryptoInDatabase()
        {
            _keyService.GetCurrent();

            _keyService.GetLastKeysCredentials(5).Count.Should().BePositive();
        }

        [Theory]
        [InlineData(5)]
        [InlineData(2)]
        [InlineData(6)]
        public void ShouldGenerateManyRsa(int qty)
        {
            _keyStore.Clear();
            var keysGenerated = new List<SigningCredentials>();
            for (int i = 0; i < qty; i++)
            {
                var sign = _keyService.Generate();
                keysGenerated.Add(sign);
            }

            var current = _keyService.GetLastKeysCredentials(qty * 2);
            foreach (var securityKey in current)
            {
                keysGenerated.Select(s => s.Key.KeyId).Should().Contain(securityKey.KeyId);
            }
        }


        [Fact]
        public void ShouldSaveCryptoAndRecover()
        {
            var newKey = _keyService.GetCurrent();

            _keyService.GetLastKeysCredentials(5).Count.Should().BePositive();

            var currentKey = _keyService.GetCurrent();
            newKey.Kid.Should().Be(currentKey.Kid);
        }

    }
}