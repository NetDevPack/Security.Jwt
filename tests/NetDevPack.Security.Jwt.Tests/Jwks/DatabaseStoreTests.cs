using NetDevPack.Security.Jwt.Tests.Warmups;
using Xunit;

namespace NetDevPack.Security.Jwt.Tests.Jwks
{
    [Trait("Category", "Database Tests")]
    public class DatabaseStoreTests : GenericStoreServiceTest<WarmupDatabaseInMemory>
    {
        public DatabaseStoreTests(WarmupDatabaseInMemory unifiedContext) : base(unifiedContext)
        {
        }
    }
}