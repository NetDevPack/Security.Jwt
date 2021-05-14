using NetDevPack.Security.JwtSigningCredentials.Tests.Warmups;
using Xunit;

namespace NetDevPack.Security.JwtSigningCredentials.Tests.Jwks
{
    [Trait("Category", "InMemory Tests")]
    public class FileSystemStoreTests : GenericStoreServiceTest<WarmupFileStore>
    {
        public FileSystemStoreTests(WarmupFileStore unifiedContext) : base(unifiedContext)
        {
        }
    }
}