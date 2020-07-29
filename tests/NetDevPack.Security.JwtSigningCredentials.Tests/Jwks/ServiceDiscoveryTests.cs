using FluentAssertions;
using NetDevPack.Security.JwtSigningCredentials.Tests.Infra;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace NetDevPack.Security.JwtSigningCredentials.Tests.Jwks
{
    public class ServiceDiscoveryTests
    {
        [Fact]
        public async Task ShouldGetJwks()
        {
            var server = new Server();

            var client = server.CreateClient();
            var request = new HttpRequestMessage(HttpMethod.Get, "http://localhost/jwks");

            var response = await client.SendAsync(request);

            response.EnsureSuccessStatusCode();
        }

        [Fact]
        public async Task ShouldJwksHasKeys()
        {
            var server = new Server();

            var client = server.CreateClient();
            var request = new HttpRequestMessage(HttpMethod.Get, "http://localhost/jwks");

            var response = await client.SendAsync(request);

            response.EnsureSuccessStatusCode();

            var keys = JsonConvert.DeserializeObject<JsonWebKeySet>(await response.Content.ReadAsStringAsync());

            keys.Should().NotBeNull();
            keys.Keys.Should().NotBeEmpty();
            keys.Keys.Should().NotContainNulls();
        }
    }
}
