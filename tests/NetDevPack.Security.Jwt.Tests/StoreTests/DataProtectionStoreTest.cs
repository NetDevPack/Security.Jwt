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

    [Fact]
    public async Task Should_Read_Default_Revocation_Reason()
    {
        var keyMaterial = await StoreRandomKey();
        /*Revoke*/
        await _store.Revoke(keyMaterial);
        await CheckRevocationReasonIsStored(keyMaterial.KeyId, DataProtectionStore.DefaultRevocationReason);
    }

    [Theory]
    [InlineData("ManualRevocation")]
    [InlineData("StolenKey")]
    public async Task Should_Read_NonDefault_Revocation_Reason(string reason)
    {
        var keyMaterial = await StoreRandomKey();
        /*Revoke with reason*/
        await _store.Revoke(keyMaterial, reason);
        await CheckRevocationReasonIsStored(keyMaterial.KeyId, reason);
    }

    private async Task CheckRevocationReasonIsStored(string keyId, string revocationReason)
    {
        var dbKey = (await _store.GetLastKeys(5)).First(w => w.KeyId == keyId);
        dbKey.Type.Should().NotBeNullOrEmpty();
        dbKey.RevokedReason.Should().BeEquivalentTo(revocationReason);
    }

    private async Task<KeyMaterial> StoreRandomKey()
    {
        var alg = Algorithm.Create(DigitalSignaturesAlgorithm.RsaSha512);
        var key = new CryptographicKey(alg);
        var keyMaterial = new KeyMaterial(key);
        await _store.Store(keyMaterial);
        return keyMaterial;
    }
}