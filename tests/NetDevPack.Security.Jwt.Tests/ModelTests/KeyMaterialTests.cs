using System;
using NetDevPack.Security.Jwt.Core.Jwa;
using NetDevPack.Security.Jwt.Core.Model;
using Xunit;

namespace NetDevPack.Security.Jwt.Tests.ModelTests;

public class KeyMaterialTests
{
    [Fact]
    public void Should_Start_CreationDate_With_Utc_Kind()
    {
        var alg = Algorithm.Create(DigitalSignaturesAlgorithm.HmacSha256);
        var key = new CryptographicKey(alg);

        var keyMaterial = new KeyMaterial(key);

        Assert.Equal(DateTimeKind.Utc, keyMaterial.CreationDate.Kind);
    }

    [Fact]
    public void Should_Define_ExpiredAt_With_Utc_Kind()
    {
        var alg = Algorithm.Create(DigitalSignaturesAlgorithm.HmacSha256);
        var key = new CryptographicKey(alg);
        var keyMaterial = new KeyMaterial(key);

        keyMaterial.Revoke();

        Assert.Equal(DateTimeKind.Utc, keyMaterial.ExpiredAt?.Kind);
    }
}