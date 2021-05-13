using System;
using System.Collections.Generic;
using System.Text;
using NetDevPack.Security.JwtSigningCredentials.Tests.Warmups;
using Xunit;

namespace NetDevPack.Security.JwtSigningCredentials.Tests.Jwks
{
    [Trait("Category", "DataProtection Tests")]
    public class DataProtectionStoreTest : GenericStoreServiceTest<WarmupFileStore>
    {
        public DataProtectionStoreTest(WarmupFileStore unifiedContext) : base(unifiedContext)
        {
        }
    }
}
