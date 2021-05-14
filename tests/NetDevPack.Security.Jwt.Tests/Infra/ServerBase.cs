using System.Net.Http;
using Microsoft.AspNetCore.TestHost;

namespace NetDevPack.Security.JwtSigningCredentials.Tests.Infra
{
    public abstract class ServerBase
    {
        public abstract string JwkEndpoint { get; set; }
        public abstract TestServer CreateServer(bool useCache = true);
        public abstract HttpClient CreateClient(bool useCache = true);
    }
}