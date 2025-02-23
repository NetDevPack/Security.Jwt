using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Bogus;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Core;
using NetDevPack.Security.Jwt.Core.DefaultStore;
using NetDevPack.Security.Jwt.Core.Interfaces;
using NetDevPack.Security.Jwt.Core.Jwa;
using NetDevPack.Security.Jwt.Core.Model;
using NetDevPack.Security.Jwt.Tests.Warmups;
using Xunit;

namespace NetDevPack.Security.Jwt.Tests.StoreTests;
public abstract class GenericStoreServiceTest<TWarmup> : IClassFixture<TWarmup>
    where TWarmup : class, IWarmupTest
{
    private static SemaphoreSlim TestSync = new(1);
    protected readonly IJsonWebKeyStore _store;
    protected readonly IJwtService _jwtService;
    private readonly IOptions<JwtOptions> _options;
    public TWarmup WarmupData { get; }

    public GenericStoreServiceTest(TWarmup warmup)
    {
        WarmupData = warmup;
        _store = WarmupData.Services.GetRequiredService<IJsonWebKeyStore>();
        _jwtService = WarmupData.Services.GetRequiredService<IJwtService>();
        _options = WarmupData.Services.GetRequiredService<IOptions<JwtOptions>>();
        this.WarmupData.Clear();
    }


    [Fact]
    public async Task Should_Save_Crypto()
    {
        var key = new CryptographicKey(DigitalSignaturesAlgorithm.RsaSsaPssSha256);
        var model = new KeyMaterial(key);
        await _store.Store(model);
    }

    [Fact]
    public async Task ShouldNotThrowExceptionWhenGetSignManyTimes()
    {
        await GenerateKey();
        var currentA = await _store.GetCurrent();
        var currentB = await _store.GetCurrent();
        var currentC = await _store.GetCurrent();

        var currentD = await _store.GetCurrent();
        var token = new SecurityTokenDescriptor()
        {
            Issuer = "test.jwt",
            Subject = new ClaimsIdentity(),
            Expires = DateTime.UtcNow.AddMinutes(3),
            SigningCredentials = new SigningCredentials(currentD?.GetSecurityKey(), _options.Value.Jws)
        };
    }

    [Theory]
    [InlineData(DigitalSignaturesAlgorithm.HmacSha256)]
    [InlineData(DigitalSignaturesAlgorithm.HmacSha384)]
    [InlineData(DigitalSignaturesAlgorithm.HmacSha512)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSha256)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSha384)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSha512)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha256)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha384)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha512)]
    [InlineData(DigitalSignaturesAlgorithm.EcdsaSha256)]
    [InlineData(DigitalSignaturesAlgorithm.EcdsaSha384)]
    [InlineData(DigitalSignaturesAlgorithm.EcdsaSha512)]
    public async Task Should_Remove_Private_Key_And_Update(string algorithm)
    {
        var alg = Algorithm.Create(algorithm);
        var key = new CryptographicKey(alg);
        var keyMaterial = new KeyMaterial(key);
        await _store.Store(keyMaterial);

        /*Remove private*/
        await _store.Revoke(keyMaterial);

        var current = await _store.Get(keyMaterial.KeyId);
        current?.GetSecurityKey().HasPrivateKey.Should().BeFalse();
    }


    [Theory]
    [InlineData(DigitalSignaturesAlgorithm.HmacSha256)]
    [InlineData(DigitalSignaturesAlgorithm.HmacSha384)]
    [InlineData(DigitalSignaturesAlgorithm.HmacSha512)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSha256)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSha384)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSha512)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha256)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha384)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha512)]
    [InlineData(DigitalSignaturesAlgorithm.EcdsaSha256)]
    [InlineData(DigitalSignaturesAlgorithm.EcdsaSha384)]
    [InlineData(DigitalSignaturesAlgorithm.EcdsaSha512)]
    public async Task Should_Keep_Public_Key_After_Update_A_Expired_Jwk(string algorithm)
    {
        var alg = Algorithm.Create(algorithm);
        var key = new CryptographicKey(alg);
        var keyMaterial = new KeyMaterial(key);
        await _store.Store(keyMaterial);
        /*Remove private*/
        await _store.Revoke(keyMaterial);

        var dbKey = (await _store.GetLastKeys(5)).First(w => w.KeyId == keyMaterial.KeyId);
        dbKey.Type.Should().NotBeNullOrEmpty();

        var jsonWebKey = dbKey.GetSecurityKey();
        jsonWebKey.HasPrivateKey.Should().BeFalse();
        switch (jsonWebKey.Kty)
        {
            case JsonWebAlgorithmsKeyTypes.EllipticCurve:
                jsonWebKey.X.Should().NotBeNullOrEmpty();
                jsonWebKey.Y.Should().NotBeNullOrEmpty();
                break;
            case JsonWebAlgorithmsKeyTypes.RSA:
                jsonWebKey.N.Should().NotBeNullOrEmpty();
                jsonWebKey.E.Should().NotBeNullOrEmpty();
                break;
            case JsonWebAlgorithmsKeyTypes.Octet:
                jsonWebKey.K.Should().NotBeNullOrEmpty();
                break;
        }
    }


    [Theory]
    [InlineData(DigitalSignaturesAlgorithm.HmacSha256)]
    [InlineData(DigitalSignaturesAlgorithm.HmacSha384)]
    [InlineData(DigitalSignaturesAlgorithm.HmacSha512)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSha256)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSha384)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSha512)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha256)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha384)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha512)]
    [InlineData(DigitalSignaturesAlgorithm.EcdsaSha256)]
    [InlineData(DigitalSignaturesAlgorithm.EcdsaSha384)]
    [InlineData(DigitalSignaturesAlgorithm.EcdsaSha512)]
    public async Task Should_Remove_Private_Key_After_Update_A_Expired_Jwk(string algorithm)
    {

        var alg = Algorithm.Create(algorithm);
        var key = new CryptographicKey(alg);
        var keyMaterial = new KeyMaterial(key);
        await _store.Store(keyMaterial);
        /*Remove private*/
        await _store.Revoke(keyMaterial);

        var keyDb = (await _store.GetLastKeys(5)).FirstOrDefault(w => w.KeyId == keyMaterial.KeyId);
        var jsonWebKey = keyDb?.GetSecurityKey();

        jsonWebKey!.Kty.Should().NotBeNullOrEmpty();
        jsonWebKey.HasPrivateKey.Should().BeFalse();
        switch (jsonWebKey.Kty)
        {
            case JsonWebAlgorithmsKeyTypes.EllipticCurve:
                jsonWebKey.D.Should().BeNullOrEmpty();
                break;
            case JsonWebAlgorithmsKeyTypes.RSA:
                jsonWebKey.D.Should().BeNullOrEmpty();
                jsonWebKey.DP.Should().BeNullOrEmpty();
                jsonWebKey.DQ.Should().BeNullOrEmpty();
                jsonWebKey.P.Should().BeNullOrEmpty();
                jsonWebKey.Q.Should().BeNullOrEmpty();
                jsonWebKey.QI.Should().BeNullOrEmpty();
                break;
            case JsonWebAlgorithmsKeyTypes.Octet:
                jsonWebKey.K.Should().NotBeNullOrEmpty();
                break;
        }
    }


    [Theory]
    [InlineData(EncryptionAlgorithmKey.RsaOAEP, EncryptionAlgorithmContent.Aes128CbcHmacSha256)]
    [InlineData(EncryptionAlgorithmKey.RsaPKCS1, EncryptionAlgorithmContent.Aes128CbcHmacSha256)]
    [InlineData(EncryptionAlgorithmKey.Aes128KW, EncryptionAlgorithmContent.Aes128CbcHmacSha256)]
    [InlineData(EncryptionAlgorithmKey.Aes256KW, EncryptionAlgorithmContent.Aes128CbcHmacSha256)]
    [InlineData(EncryptionAlgorithmKey.RsaOAEP, EncryptionAlgorithmContent.Aes256CbcHmacSha512)]
    [InlineData(EncryptionAlgorithmKey.RsaPKCS1, EncryptionAlgorithmContent.Aes256CbcHmacSha512)]
    [InlineData(EncryptionAlgorithmKey.Aes128KW, EncryptionAlgorithmContent.Aes256CbcHmacSha512)]
    [InlineData(EncryptionAlgorithmKey.Aes256KW, EncryptionAlgorithmContent.Aes256CbcHmacSha512)]
    [InlineData(EncryptionAlgorithmKey.RsaOAEP, EncryptionAlgorithmContent.Aes192CbcHmacSha384)]
    [InlineData(EncryptionAlgorithmKey.RsaPKCS1, EncryptionAlgorithmContent.Aes192CbcHmacSha384)]
    [InlineData(EncryptionAlgorithmKey.Aes128KW, EncryptionAlgorithmContent.Aes192CbcHmacSha384)]
    [InlineData(EncryptionAlgorithmKey.Aes256KW, EncryptionAlgorithmContent.Aes192CbcHmacSha384)]
    public async Task Should_Remove_Private_Key_From_Jwe_After_Update_A_Expired_Jwk(string algorithm, string encryption)
    {
        var alg = Algorithm.Create(algorithm).WithContentEncryption(encryption);

        var key = new CryptographicKey(alg);
        var privateKey = new KeyMaterial(key);

        await _store.Store(privateKey);

        /*Remove private*/
        await _store.Revoke(privateKey);

        var keyDb = (await _store.GetLastKeys(5)).First(w => w.KeyId == privateKey.KeyId);
        var jsonWebKey = keyDb.GetSecurityKey();

        jsonWebKey.Kty.Should().NotBeNullOrEmpty();
        jsonWebKey.HasPrivateKey.Should().BeFalse();
        switch (jsonWebKey.Kty)
        {
            case JsonWebAlgorithmsKeyTypes.EllipticCurve:
                jsonWebKey.D.Should().BeNullOrEmpty();
                break;
            case JsonWebAlgorithmsKeyTypes.RSA:
                jsonWebKey.D.Should().BeNullOrEmpty();
                jsonWebKey.DP.Should().BeNullOrEmpty();
                jsonWebKey.DQ.Should().BeNullOrEmpty();
                jsonWebKey.P.Should().BeNullOrEmpty();
                jsonWebKey.Q.Should().BeNullOrEmpty();
                jsonWebKey.QI.Should().BeNullOrEmpty();
                break;
            case JsonWebAlgorithmsKeyTypes.Octet:
                jsonWebKey.K.Should().NotBeNullOrEmpty();
                break;
        }
    }

    [Theory]
    [InlineData(DigitalSignaturesAlgorithm.HmacSha256)]
    [InlineData(DigitalSignaturesAlgorithm.HmacSha384)]
    [InlineData(DigitalSignaturesAlgorithm.HmacSha512)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSha256)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSha384)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSha512)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha256)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha384)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha512)]
    [InlineData(DigitalSignaturesAlgorithm.EcdsaSha256)]
    [InlineData(DigitalSignaturesAlgorithm.EcdsaSha384)]
    [InlineData(DigitalSignaturesAlgorithm.EcdsaSha512)]
    public async Task Should_Save_Crypto_And_Recover(string algorithm)
    {
        var alg = Algorithm.Create(algorithm);
        var key = new CryptographicKey(alg);
        var keyMaterial = new KeyMaterial(key);

        await _store.Store(keyMaterial);

        var newKey = await _store.GetCurrent();

        (await _store.GetLastKeys(5)).Count.Should().BePositive();

        var currentKey = await _store.GetCurrent();
        newKey?.KeyId.Should().Be(currentKey?.KeyId);
    }


    [Theory]
    [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha256)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha384)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSsaPssSha512)]
    [InlineData(DigitalSignaturesAlgorithm.EcdsaSha256)]
    [InlineData(DigitalSignaturesAlgorithm.EcdsaSha384)]
    [InlineData(DigitalSignaturesAlgorithm.EcdsaSha512)]
    public async Task Should_Save_Probabilistic_Jwk_Recover_And_Signing(string algorithm)
    {
        var handler = new JsonWebTokenHandler();
        var now = DateTime.Now;

        // Generate right now and in memory
        var newKey = new KeyMaterial(new CryptographicKey(algorithm));
        await _store.Store(newKey);

        // recovered from database
        var currentKey = await _store.GetCurrent();

        newKey.KeyId.Should().Be(currentKey?.KeyId);
        var claims = new ClaimsIdentity(GenerateClaim().Generate(5));
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "me",
            Audience = "you",
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            Subject = claims,
            SigningCredentials = new SigningCredentials(newKey, algorithm)
        };

        var descriptorFromDb = new SecurityTokenDescriptor
        {
            Issuer = "me",
            Audience = "you",
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            Subject = claims,
            SigningCredentials = new SigningCredentials(currentKey, algorithm)
        };

        var jwt1 = handler.CreateToken(descriptor);
        var jwt2 = handler.CreateToken(descriptorFromDb);

        jwt1.Should().NotBe(jwt2);
    }




    [Theory]
    [InlineData(DigitalSignaturesAlgorithm.HmacSha256)]
    [InlineData(DigitalSignaturesAlgorithm.HmacSha384)]
    [InlineData(DigitalSignaturesAlgorithm.HmacSha512)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSha256)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSha384)]
    [InlineData(DigitalSignaturesAlgorithm.RsaSha512)]
    public async Task ShouldSaveDeterministicJwkRecoverAndSigning(string algorithm)
    {
        await this.WarmupData.Clear();

        var handler = new JsonWebTokenHandler();
        var now = DateTime.Now;

        // Generate right now and in memory
        var newKey = new CryptographicKey(algorithm);
        await _store.Store(new KeyMaterial(newKey));
        // recovered from database
        var currentKey = await _store.GetCurrent();

        newKey.Key.KeyId.Should().Be(currentKey?.KeyId);

        var claims = new ClaimsIdentity(GenerateClaim().Generate(5));
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "me",
            Audience = "you",
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            Subject = claims,
            SigningCredentials = new SigningCredentials(newKey, algorithm)
        };
        var descriptorFromDb = new SecurityTokenDescriptor
        {
            Issuer = "me",
            Audience = "you",
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            Subject = claims,
            SigningCredentials = new SigningCredentials(currentKey, algorithm)
        };

        var jwt1 = handler.CreateToken(descriptor);
        var jwt2 = handler.CreateToken(descriptorFromDb);

        jwt1.Should().Be(jwt2);
    }

    [Theory]
    [InlineData(EncryptionAlgorithmKey.RsaOAEP, EncryptionAlgorithmContent.Aes128CbcHmacSha256)]
    [InlineData(EncryptionAlgorithmKey.RsaPKCS1, EncryptionAlgorithmContent.Aes128CbcHmacSha256)]
    [InlineData(EncryptionAlgorithmKey.Aes128KW, EncryptionAlgorithmContent.Aes128CbcHmacSha256)]
    [InlineData(EncryptionAlgorithmKey.Aes256KW, EncryptionAlgorithmContent.Aes128CbcHmacSha256)]
    [InlineData(EncryptionAlgorithmKey.RsaOAEP, EncryptionAlgorithmContent.Aes256CbcHmacSha512)]
    [InlineData(EncryptionAlgorithmKey.RsaPKCS1, EncryptionAlgorithmContent.Aes256CbcHmacSha512)]
    [InlineData(EncryptionAlgorithmKey.Aes128KW, EncryptionAlgorithmContent.Aes256CbcHmacSha512)]
    [InlineData(EncryptionAlgorithmKey.Aes256KW, EncryptionAlgorithmContent.Aes256CbcHmacSha512)]
    [InlineData(EncryptionAlgorithmKey.RsaOAEP, EncryptionAlgorithmContent.Aes192CbcHmacSha384)]
    [InlineData(EncryptionAlgorithmKey.RsaPKCS1, EncryptionAlgorithmContent.Aes192CbcHmacSha384)]
    [InlineData(EncryptionAlgorithmKey.Aes128KW, EncryptionAlgorithmContent.Aes192CbcHmacSha384)]
    [InlineData(EncryptionAlgorithmKey.Aes256KW, EncryptionAlgorithmContent.Aes192CbcHmacSha384)]
    public async Task ShouldSaveJweRecoverAndEncrypt(string algorithm, string encryption)
    {
        await WarmupData.Clear();
        var handler = new JsonWebTokenHandler();
        var now = DateTime.Now;

        // Generate right now and in memory
        var newKey = new KeyMaterial(new CryptographicKey(Algorithm.Create(algorithm).WithContentEncryption(encryption)));

        await _store.Store(newKey);
        // recovered from database
        var currentKey = await _store.Get(newKey.KeyId);


        newKey.KeyId.Should().Be(currentKey?.KeyId);
        var claims = new ClaimsIdentity(GenerateClaim().Generate(5));
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "me",
            Audience = "you",
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            Subject = claims,
            EncryptingCredentials = new EncryptingCredentials(newKey, algorithm, encryption)
        };
        var descriptorFromDb = new SecurityTokenDescriptor
        {
            Issuer = "me",
            Audience = "you",
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            Subject = claims,
            EncryptingCredentials = new EncryptingCredentials(currentKey, algorithm, encryption)
        };

        var jwt1 = handler.CreateToken(descriptor);
        var jwt2 = handler.CreateToken(descriptorFromDb);

        var result = await handler.ValidateTokenAsync(jwt1,
            new TokenValidationParameters
            {
                ValidIssuer = "me",
                ValidAudience = "you",
                RequireSignedTokens = false,
                TokenDecryptionKey = currentKey
            });
        result.IsValid.Should().BeTrue();

        result = await handler.ValidateTokenAsync(jwt2,
            new TokenValidationParameters
            {
                ValidIssuer = "me",
                ValidAudience = "you",
                RequireSignedTokens = false,
                TokenDecryptionKey = currentKey
            });

        result.IsValid.Should().BeTrue();

    }

    [Fact]
    public async Task ShouldGenerateAndValidateJweAndJws()
    {
        await WarmupData.Clear();

        var handler = new JsonWebTokenHandler();
        var now = DateTime.Now;

        // Generate right now and in memory
        var newKey = new CryptographicKey(Algorithm.Create(AlgorithmType.RSA, JwtType.Both));

        var encryptingCredentials = new EncryptingCredentials(newKey, EncryptionAlgorithmKey.RsaOAEP, EncryptionAlgorithmContent.Aes128CbcHmacSha256);
        var signingCredentials = new SigningCredentials(newKey, DigitalSignaturesAlgorithm.RsaSsaPssSha256);

        var claims = new ClaimsIdentity(GenerateClaim().Generate(5));
        var descriptorJws = new SecurityTokenDescriptor
        {
            Issuer = "me",
            Audience = "you",
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            Subject = claims,
            SigningCredentials = signingCredentials
        };
        var descriptorJwe = new SecurityTokenDescriptor
        {
            Issuer = "me",
            Audience = "you",
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            Subject = claims,
            EncryptingCredentials = encryptingCredentials
        };

        var jws = handler.CreateToken(descriptorJws);
        var jwe = handler.CreateToken(descriptorJwe);

        var result = await handler.ValidateTokenAsync(jws,
            new TokenValidationParameters
            {
                ValidIssuer = "me",
                ValidAudience = "you",
                IssuerSigningKey = signingCredentials.Key
            });
        result.IsValid.Should().BeTrue();

        result = await handler.ValidateTokenAsync(jwe,
            new TokenValidationParameters
            {
                ValidIssuer = "me",
                ValidAudience = "you",
                RequireSignedTokens = false,
                TokenDecryptionKey = encryptingCredentials.Key
            });

        result.IsValid.Should().BeTrue();

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

    [Fact]
    public async Task Should_Generate_Different_Keys_For_JWS_And_JWE_And_Retrieve_Them_Correctly()
    {
        var defaultVal =  await _jwtService.GetCurrentSecurityKey();
        var jwe =  await _jwtService.GetCurrentSecurityKey(JwtKeyType.Jwe);
        var jws =  await _jwtService.GetCurrentSecurityKey(JwtKeyType.Jws);

        var getLast2DefaultVal =  await _jwtService.GetLastKeys(1);
        var getLastJwe =  (await _jwtService.GetLastKeys(1, JwtKeyType.Jwe)).First();
        var getLastJws =  (await _jwtService.GetLastKeys(1, JwtKeyType.Jws)).First();

        jws.KeyId.Should().NotBe(jwe.KeyId);
        getLastJws.KeyId.Should().NotBe(getLastJwe.KeyId);
        defaultVal.KeyId.Should().Be(jws.KeyId);
        jwe.KeyId.Should().Be(getLastJwe.KeyId);
        jws.KeyId.Should().Be(getLastJws.KeyId);

        getLast2DefaultVal.Should().HaveCount(2);
        getLast2DefaultVal.Should().ContainSingle(x => x.Use == "enc");
        getLast2DefaultVal.Should().ContainSingle(x => x.Use == "sig");
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



    private Task GenerateKey()
    {
        var key = new CryptographicKey(DigitalSignaturesAlgorithm.RsaSsaPssSha256);
        var model = new KeyMaterial(key);
        return _store.Store(model);
    }


    public Faker<Claim> GenerateClaim()
    {
        return new Faker<Claim>().CustomInstantiator(f => new Claim(f.Internet.DomainName(), f.Lorem.Text()));
    }
}