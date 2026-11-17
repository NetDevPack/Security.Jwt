using System.Threading.Tasks;
using AwesomeAssertions;
using Microsoft.Extensions.DependencyInjection;
using NetDevPack.Security.Jwt.Core.Interfaces;
using Xunit;

namespace NetDevPack.Security.Jwt.Tests.StoreTests;

[Trait("Category", "InMemory Tests")]
public class InMemoryStoreIsolationTests
{
    private static ServiceProvider CreateProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMemoryCache();
        services.AddJwksManager().PersistKeysInMemory();
        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task ServiceProviders_ShouldNotShareKeys()
    {
        await using var first = CreateProvider();
        await using var second = CreateProvider();

        using (var scope = first.CreateScope())
            await scope.ServiceProvider.GetRequiredService<IJwtService>().GenerateKey();

        using (var scope = second.CreateScope())
            (await scope.ServiceProvider.GetRequiredService<IJsonWebKeyStore>().GetLastKeys(5)).Should().BeEmpty();
    }

    [Fact]
    public async Task Scopes_OfTheSameServiceProvider_ShouldShareKeys()
    {
        await using var provider = CreateProvider();

        string keyId;
        using (var scope = provider.CreateScope())
            keyId = (await scope.ServiceProvider.GetRequiredService<IJwtService>().GenerateKey()).KeyId;

        using (var scope = provider.CreateScope())
            (await scope.ServiceProvider.GetRequiredService<IJsonWebKeyStore>().Get(keyId)).Should().NotBeNull();
    }
}
