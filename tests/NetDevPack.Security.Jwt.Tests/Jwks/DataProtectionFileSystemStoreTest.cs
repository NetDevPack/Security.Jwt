using NetDevPack.Security.Jwt.Tests.Warmups;
using Xunit;

namespace NetDevPack.Security.Jwt.Tests.Jwks
{
    [Trait("Category", "DataProtection With Custom FileSystem Tests")]
    public class DataProtectionFileSystemStoreTest : GenericStoreServiceTest<WarmupDataProtectionFileSystemStore>
    {
        public DataProtectionFileSystemStoreTest(WarmupDataProtectionFileSystemStore unifiedContext) : base(unifiedContext)
        {
        }
    }
}