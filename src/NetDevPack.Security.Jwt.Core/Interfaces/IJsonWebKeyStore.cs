using System.Collections.ObjectModel;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Core.Model;

namespace NetDevPack.Security.Jwt.Core.Interfaces;

public interface IJsonWebKeyStore
{
    Task Store(KeyMaterial keyMaterial);
    Task<KeyMaterial?> GetCurrent();
    Task Revoke(KeyMaterial? keyMaterial);
    Task<ReadOnlyCollection<KeyMaterial>> GetLastKeys(int quantity);
    Task<KeyMaterial?> Get(string keyId);
    Task Clear();
}