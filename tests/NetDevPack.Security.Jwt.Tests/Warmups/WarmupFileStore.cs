using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using NetDevPack.Security.Jwt.Core;
using NetDevPack.Security.Jwt.Core.Interfaces;
using NetDevPack.Security.Jwt.Store.FileSystem;

namespace NetDevPack.Security.Jwt.Tests.Warmups
{
    public class WarmupFileStore : IWarmupTest
    {
        private readonly IJsonWebKeyStore _jsonWebKeyStore;
        public ServiceProvider Services { get; set; }
        public WarmupFileStore()
        {
            var serviceCollection = new ServiceCollection();
            serviceCollection.AddLogging();
            serviceCollection.AddMemoryCache();
            serviceCollection.AddJwksManager().PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(Directory.GetCurrentDirectory(), "/filestore")));

            Services = serviceCollection.BuildServiceProvider();
            _jsonWebKeyStore = Services.GetRequiredService<IJsonWebKeyStore>();
        }

        public async Task Clear()
        {
           await _jsonWebKeyStore.Clear();
        }
    }
}
