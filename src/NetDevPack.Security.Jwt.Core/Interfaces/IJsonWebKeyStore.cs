using System.Collections.ObjectModel;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Core.Jwa;
using NetDevPack.Security.Jwt.Core.Model;

namespace NetDevPack.Security.Jwt.Core.Interfaces;

public interface IJsonWebKeyStore
{
    Task<KeyMaterial> Store(KeyMaterial keyMaterial);
    Task<KeyMaterial> GetCurrent(JwtKeyType jwtKeyType = JwtKeyType.Jws, bool bypassCache = false);
    Task Revoke(KeyMaterial keyMaterial, string reason=default);
    Task<ReadOnlyCollection<KeyMaterial>> GetLastKeys(int quantity, JwtKeyType? jwtKeyType = null);
    Task<KeyMaterial> Get(string keyId);
    Task Clear();
}