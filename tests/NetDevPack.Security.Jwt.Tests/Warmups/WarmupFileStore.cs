using System;
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
        public DirectoryInfo _directoryInfo;

        public WarmupFileStore()
        {
            _directoryInfo = TempDirectoryTest();

            var serviceCollection = new ServiceCollection();
            serviceCollection.AddLogging();
            serviceCollection.AddMemoryCache();
            serviceCollection.AddJwksManager().PersistKeysToFileSystem(_directoryInfo);
            Services = serviceCollection.BuildServiceProvider();
            _jsonWebKeyStore = Services.GetRequiredService<IJsonWebKeyStore>();
        }

        public DirectoryInfo TempDirectoryTest()
        {
            // Créer un répertoire temporaire unique
            var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            return Directory.CreateDirectory(tempDir);
        }

        public async Task Clear()
        {
            await _jsonWebKeyStore.Clear();
            _directoryInfo.Delete(true);
            Directory.CreateDirectory(_directoryInfo.FullName);
        }
    }
}
