using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using NetDevPack.Security.Jwt.Core.Interfaces;
using NetDevPack.Security.Jwt.Core.Jwa;

namespace NetDevPack.Security.Jwt.Tests.Warmups;

public class WarmupDatabaseInMemoryStore : IWarmupTest
{
    private readonly IJsonWebKeyStore _jsonWebKeyStore;
    public ServiceProvider Services { get; set; }

    public WarmupDatabaseInMemoryStore()
    {
        var serviceCollection = new ServiceCollection();

        void DatabaseOptions(DbContextOptionsBuilder opt) => opt.UseInMemoryDatabase("Tests").EnableSensitiveDataLogging();

        serviceCollection.AddMemoryCache();
        serviceCollection.AddLogging();
        serviceCollection.AddDbContext<AspNetGeneralContext>(DatabaseOptions);

        serviceCollection.AddJwksManager()
            .PersistKeysToDatabaseStore<AspNetGeneralContext>();
        Services = serviceCollection.BuildServiceProvider();
        _jsonWebKeyStore = Services.GetRequiredService<IJsonWebKeyStore>();
    }

    public async Task Clear()
    {
        await _jsonWebKeyStore.Clear();
    }
    public void DetachAll()
    {

        var database = Services.GetService<AspNetGeneralContext>();
        foreach (var dbEntityEntry in database!.ChangeTracker.Entries())
        {
            if (dbEntityEntry.Entity != null)
            {
                dbEntityEntry.State = EntityState.Detached;
            }
        }

    }
}