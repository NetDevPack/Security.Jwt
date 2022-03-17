using NetDevPack.Security.Jwt.Tests.Warmups;
using Xunit;

namespace NetDevPack.Security.Jwt.Tests.StoreTests;

[Trait("Category", "InMemory Tests")]
public class InMemoryStoreTests : GenericStoreServiceTest<WarmupInMemoryStore>
{
    public InMemoryStoreTests(WarmupInMemoryStore unifiedContext) : base(unifiedContext)
    {
    }
}