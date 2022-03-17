using NetDevPack.Security.Jwt.Tests.Warmups;
using Xunit;

namespace NetDevPack.Security.Jwt.Tests.StoreTests;

[Trait("Category", "DataProtection Tests")]
public class DataProtectionStoreTest : GenericStoreServiceTest<WarmupDataProtectionStore>
{
    public DataProtectionStoreTest(WarmupDataProtectionStore unifiedContext) : base(unifiedContext)
    {
    }
}