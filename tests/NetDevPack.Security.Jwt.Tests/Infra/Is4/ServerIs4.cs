using System;
using System.IO;
using System.Net.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using NetDevPack.Security.Jwt.IdentityServer4;
using NetDevPack.Security.Jwt.IdentityServer4.Tests;

namespace NetDevPack.Security.Jwt.Tests.Infra.Is4
{
    public class ServerIs4 : ServerBase
    {
        private DirectoryInfo _keysRepository;
        public override string JwkEndpoint { get; set; } = "http://localhost:6001/.well-known/openid-configuration/jwks";

        public override TestServer CreateServer(bool useCache = true)
        {
            _keysRepository = new DirectoryInfo(Path.Combine(Directory.GetCurrentDirectory(), "is4-test"));
            _keysRepository.Create();
            Clear();
            return new TestServer(new WebHostBuilder()
                .ConfigureServices(services =>
                {
                    services
                        .AddLogging()
                        .AddMemoryCache()
                        .AddDataProtection().PersistKeysToFileSystem(_keysRepository);

                    services.AddJwksManager().IdentityServer4AutoJwksManager();
                    var builder = services.AddIdentityServer()
                        .AddInMemoryIdentityResources(Config.GetIdentityResources())
                        .AddInMemoryApiResources(Config.GetApis())
                        .AddInMemoryClients(Config.GetClients());

                })
                .Configure(app =>
                {
                    app.UseIdentityServer();
                    app.Map(new PathString("/renew"), x => x.UseMiddleware<JwkRenewMiddleware>());
                })
                .UseUrls("http://localhost:6001/")
            );
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