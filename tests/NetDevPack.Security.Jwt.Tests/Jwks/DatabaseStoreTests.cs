using NetDevPack.Security.JwtSigningCredentials.Tests.Warmups;
using Xunit;

namespace NetDevPack.Security.JwtSigningCredentials.Tests.Jwks
{
    [Trait("Category", "Database Tests")]
    public class DatabaseStoreTests : GenericStoreServiceTest<WarmupDatabaseInMemory>
    {
        public DatabaseStoreTests(WarmupDatabaseInMemory unifiedContext) : base(unifiedContext)
        {
        }
    }
}