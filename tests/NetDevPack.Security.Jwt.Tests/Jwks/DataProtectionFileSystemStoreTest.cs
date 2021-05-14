using NetDevPack.Security.JwtSigningCredentials.Tests.Warmups;
using Xunit;

namespace NetDevPack.Security.JwtSigningCredentials.Tests.Jwks
{
    [Trait("Category", "DataProtection With Custom FileSystem Tests")]
    public class DataProtectionFileSystemStoreTest : GenericStoreServiceTest<WarmupDataProtectionFileSystemStore>
    {
        public DataProtectionFileSystemStoreTest(WarmupDataProtectionFileSystemStore unifiedContext) : base(unifiedContext)
        {
        }
    }
}