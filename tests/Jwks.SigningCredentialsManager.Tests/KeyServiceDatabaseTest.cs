using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.Linq;
using Xunit;
using Xunit.Abstractions;

namespace Jwks.SigningCredentialsManager.Tests
{
    public class KeyServiceDatabaseTest : IClassFixture<WarmupDatabaseInMemory>
    {
        private readonly AspNetGeneralContext _database;
        private readonly IKeyService _keyService;
        private ITestOutputHelper _output;
        public WarmupDatabaseInMemory DatabaseInMemoryData { get; }
        public KeyServiceDatabaseTest(WarmupDatabaseInMemory databaseInMemory, ITestOutputHelper output)
        {
            _output = output;
            DatabaseInMemoryData = databaseInMemory;
            _keyService = DatabaseInMemoryData.Services.GetRequiredService<IKeyService>();
            _database = DatabaseInMemoryData.Services.GetRequiredService<AspNetGeneralContext>();

        }

        [Fact]
        public void ShouldSaveCryptoInDatabase()
        {
            _keyService.GetCurrent();

            _database.SecurityKeys.Count().Should().BePositive();
        }


        [Theory]
        [InlineData(5)]
        [InlineData(2)]
        [InlineData(6)]
        public void ShouldGenerateManyRsa(int quantity)
        {
            _database.SecurityKeys.RemoveRange(_database.SecurityKeys.ToList());
            var keysGenerated = new List<SigningCredentials>();
            for (int i = 0; i < quantity; i++)
            {
                var sign = _keyService.Generate();
                keysGenerated.Add(sign);
            }

            var current = _keyService.GetLastKeysCredentials(quantity * 4);
            foreach (var securityKey in current)
            {
                keysGenerated.Select(s => s.Key.KeyId).Should().Contain(securityKey.KeyId);
            }
        }


        [Fact]
        public void ShouldSaveCryptoAndRecover()
        {
            var newKey = _keyService.GetCurrent();

            _database.SecurityKeys.Count().Should().BePositive();

            var currentKey = _keyService.GetCurrent();
            newKey.Kid.Should().Be(currentKey.Kid);
        }
    }
}
