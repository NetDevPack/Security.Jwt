using NetDevPack.Security.JwtSigningCredentials.Tests.Warmups;
using Xunit;

namespace NetDevPack.Security.JwtSigningCredentials.Tests.Jwks
{
    [Trait("Category", "InMemory Tests")]
    public class InMemoryStoreTests : GenericStoreServiceTest<WarmupInMemoryStore>
    {
        public InMemoryStoreTests(WarmupInMemoryStore unifiedContext) : base(unifiedContext)
        {
        }
    }
}