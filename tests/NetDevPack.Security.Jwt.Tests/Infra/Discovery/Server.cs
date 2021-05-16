using System;
using System.IO;
using System.Net.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using NetDevPack.Security.Jwt.AspNetCore;
using NetDevPack.Security.Jwt.DefaultStore;

namespace NetDevPack.Security.Jwt.Tests.Infra.Discovery
{
    public class Server : ServerBase
    {
        private DirectoryInfo _keysRepository;
        public override string JwkEndpoint { get; set; } = "http://localhost/jwks";

        public override TestServer CreateServer(bool useCache = true)
        {
            _keysRepository = DefaultKeyStorageDirectories.Instance.GetKeyStorageDirectoryForAzureWebSites();
            if (_keysRepository == null)
                _keysRepository = DefaultKeyStorageDirectories.Instance.GetKeyStorageDirectory();
            Clear();
            return new TestServer(new WebHostBuilder()
                .ConfigureServices(services =>
                {
                    services.AddLogging();
                    services.AddJwksManager();
                    if (useCache)
                        services.AddMemoryCache();

                })
                .Configure(app =>
                {
                    app.UseJwksDiscovery();
                    app.Map(new PathString("/renew"), x => x.UseMiddleware<JwkRenewMiddleware>());
                }));
        }

        public override HttpClient CreateClient(bool useCache = true)
        {
            return CreateServer(useCache).CreateClient();
        }
        public void Clear()
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            foreach (var fileInfo in _keysRepository.GetFiles("*jw*.xml"))
            {
                try
                {
                    fileInfo.Delete();
                }
                catch
                {
                    // ignored
                }
            }
        }
    }
}
