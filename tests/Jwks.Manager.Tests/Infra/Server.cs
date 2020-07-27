using Jwks.Manager.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using System.Net.Http;

namespace Jwks.Manager.Tests.Infra
{
    public class Server
    {
        public TestServer CreateServer()
        {
            return new TestServer(new WebHostBuilder()
                .ConfigureServices(services =>
                {
                    services.AddJwksManager();


                })
                .Configure(app =>
                {
                    app.UseJwksManager();
                }));
        }

        public HttpClient CreateClient()
        {
            return CreateServer().CreateClient();
        }
    }
}
