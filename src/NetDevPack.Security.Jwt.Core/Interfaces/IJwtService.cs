using System.Collections.ObjectModel;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Core.Jwa;
using NetDevPack.Security.Jwt.Core.Model;

namespace NetDevPack.Security.Jwt.Core.Interfaces;

public interface IJwtService
{
    /// <summary>
    /// By default it will use JWS options to create a Key if doesn't exist
    /// If you want to use JWE, you must select RSA. Or use `CryptographicKey` class
    /// </summary>
    /// <returns></returns>
    Task<SecurityKey> GenerateKey(JwtKeyType jwtKeyType = JwtKeyType.Jws);
    Task<SecurityKey> GetCurrentSecurityKey(JwtKeyType jwtKeyType = JwtKeyType.Jws);
    Task<SigningCredentials> GetCurrentSigningCredentials();
    Task<EncryptingCredentials> GetCurrentEncryptingCredentials();
    Task<ReadOnlyCollection<KeyMaterial>> GetLastKeys(int i, JwtKeyType jwtKeyType);
    Task<ReadOnlyCollection<KeyMaterial>> GetLastKeys(int? i = null);
    Task RevokeKey(string keyId, string reason = null);
    Task<SecurityKey> GenerateNewKey(JwtKeyType jwtKeyType = JwtKeyType.Jws);
}
[Obsolete("Deprecate, use IJwtServiceInstead")]
public interface IJsonWebKeySetService : IJwtService{}