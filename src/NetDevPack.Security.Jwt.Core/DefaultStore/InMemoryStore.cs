using System.Collections.ObjectModel;
using NetDevPack.Security.Jwt.Core.Interfaces;
using NetDevPack.Security.Jwt.Core.Jwa;
using NetDevPack.Security.Jwt.Core.Model;

namespace NetDevPack.Security.Jwt.Core.DefaultStore;

internal class InMemoryStore : IJsonWebKeyStore
{
    private static readonly List<KeyMaterial> _store = new();
    private readonly SemaphoreSlim _slim = new(1);
    internal const string DefaultRevocationReason = "Revoked";

    public Task Store(KeyMaterial keyMaterial)
    {
        if (keyMaterial is null) throw new InvalidOperationException("Can't store empty value.");

        _slim.Wait();
        _store.Add(keyMaterial);
        _slim.Release();

        return Task.CompletedTask;
    }

    public Task<KeyMaterial> GetCurrent(JwtKeyType jwtKeyType = JwtKeyType.Jws)
    {
        return Task.FromResult(_store.Where(s => s.Use == (jwtKeyType == JwtKeyType.Jws ? "sig" : "enc")).OrderByDescending(s => s.CreationDate).FirstOrDefault());
    }

    public async Task Revoke(KeyMaterial keyMaterial, string reason = null)
    {
        if(keyMaterial == null)
            return;
        var revokeReason = reason ?? DefaultRevocationReason;
        keyMaterial.Revoke(revokeReason);
        var oldOne = _store.Find(f => f.Id == keyMaterial.Id);
        if (oldOne != null)
        {
            var index = _store.FindIndex(f => f.Id == keyMaterial.Id);
            await _slim.WaitAsync();
            _store.RemoveAt(index);
            _store.Insert(index, keyMaterial);
            _slim.Release();
        }
    }

    public Task<ReadOnlyCollection<KeyMaterial>> GetLastKeys(int quantity, JwtKeyType? jwtKeyType = null)
    {
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
        return Task.FromResult(_store.FirstOrDefault(w => w.KeyId == keyId));
    }

    public Task Clear()
    {
        _store.Clear();
        return Task.CompletedTask;
    }
}