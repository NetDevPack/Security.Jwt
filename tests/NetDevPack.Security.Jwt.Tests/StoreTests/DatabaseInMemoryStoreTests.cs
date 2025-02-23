using NetDevPack.Security.Jwt.Tests.Warmups;
using Xunit;

namespace NetDevPack.Security.Jwt.Tests.StoreTests;

[Trait("Category", "DatabaseInMemory Tests")]
public class DatabaseInMemoryStoreTests : GenericStoreServiceTest<WarmupDatabaseInMemoryStore>
{
    public DatabaseInMemoryStoreTests(WarmupDatabaseInMemoryStore unifiedContext) : base(unifiedContext)
    {
    }
}