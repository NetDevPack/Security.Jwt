using System.Linq;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Tests.Warmups;
using System.Threading.Tasks;
using FluentAssertions;
using NetDevPack.Security.Jwt.Core.DefaultStore;
using NetDevPack.Security.Jwt.Core.Jwa;
using NetDevPack.Security.Jwt.Core.Model;
using Xunit;

namespace NetDevPack.Security.Jwt.Tests.StoreTests;

[Trait("Category", "DataProtection Tests")]
public class DataProtectionStoreTest : GenericStoreServiceTest<WarmupDataProtectionStore>
{
    public DataProtectionStoreTest(WarmupDataProtectionStore unifiedContext) : base(unifiedContext)
    {
    }

    
}