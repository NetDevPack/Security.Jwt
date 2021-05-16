using NetDevPack.Security.Jwt.Tests.Warmups;
using Xunit;

namespace NetDevPack.Security.Jwt.Tests.Jwks
{
    [Trait("Category", "InMemory Tests")]
    public class FileSystemStoreTests : GenericStoreServiceTest<WarmupFileStore>
    {
        public FileSystemStoreTests(WarmupFileStore unifiedContext) : base(unifiedContext)
        {
        }
    }
}