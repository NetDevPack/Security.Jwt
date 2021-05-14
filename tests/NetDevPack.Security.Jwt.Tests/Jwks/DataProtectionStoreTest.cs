using NetDevPack.Security.JwtSigningCredentials.Tests.Warmups;
using Xunit;

namespace NetDevPack.Security.JwtSigningCredentials.Tests.Jwks
{
    [Trait("Category", "DataProtection Tests")]
    public class DataProtectionStoreTest : GenericStoreServiceTest<WarmupDataProtectionStore>
    {
        public DataProtectionStoreTest(WarmupDataProtectionStore unifiedContext) : base(unifiedContext)
        {
        }
    }
}
