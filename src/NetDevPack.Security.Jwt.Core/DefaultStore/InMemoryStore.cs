using System.Collections.ObjectModel;
using NetDevPack.Security.Jwt.Core.Interfaces;
using NetDevPack.Security.Jwt.Core.Jwa;
using NetDevPack.Security.Jwt.Core.Model;

namespace NetDevPack.Security.Jwt.Core.DefaultStore;

/// <summary>
/// Keeps the keys in memory. Registered as a singleton, so each service provider (application)
/// has its own keys instead of sharing a static list with every other host in the process.
/// </summary>
internal class InMemoryStore : IJsonWebKeyStore
{
    private readonly List<KeyMaterial> _store = new();
    private readonly object _lock = new();
    internal const string DefaultRevocationReason = "Revoked";

    public Task Store(KeyMaterial keyMaterial)
    {
        if (keyMaterial is null) throw new InvalidOperationException("Can't store empty value.");

        lock (_lock)
            _store.Add(keyMaterial);

        return Task.CompletedTask;
    }

    public Task<KeyMaterial> GetCurrent(JwtKeyType jwtKeyType = JwtKeyType.Jws)
    {
        var use = jwtKeyType == JwtKeyType.Jws ? "sig" : "enc";
        lock (_lock)
            return Task.FromResult(_store.Where(s => s.Use == use).OrderByDescending(s => s.CreationDate).FirstOrDefault());
    }

    public Task Revoke(KeyMaterial keyMaterial, string reason = null)
    {
        if (keyMaterial == null)
            return Task.CompletedTask;

        keyMaterial.Revoke(reason ?? DefaultRevocationReason);
        lock (_lock)
        {
            var index = _store.FindIndex(f => f.Id == keyMaterial.Id);
            if (index >= 0)
                _store[index] = keyMaterial;
        }

        return Task.CompletedTask;
    }

    public Task<ReadOnlyCollection<KeyMaterial>> GetLastKeys(int quantity, JwtKeyType? jwtKeyType = null)
    {
        lock (_lock)
            return Task.FromResult(
                _store
                    .Where(s => jwtKeyType == null || s.Use == (jwtKeyType == JwtKeyType.Jws ? "sig" : "enc"))
                    .OrderByDescending(s => s.CreationDate)
                    .GroupBy(s => s.Use)
                    .SelectMany(g => g.Take(quantity))
                    .ToList().AsReadOnly());
    }

    public Task<KeyMaterial> Get(string keyId)
    {
        lock (_lock)
            return Task.FromResult(_store.FirstOrDefault(w => w.KeyId == keyId));
    }

    public Task Clear()
    {
        lock (_lock)
            _store.Clear();

        return Task.CompletedTask;
    }
}
