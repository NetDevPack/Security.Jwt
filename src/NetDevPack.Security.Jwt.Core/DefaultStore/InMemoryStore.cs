using System.Collections.ObjectModel;
using NetDevPack.Security.Jwt.Core.Interfaces;
using NetDevPack.Security.Jwt.Core.Model;

namespace NetDevPack.Security.Jwt.Core.DefaultStore;

internal class InMemoryStore : IJsonWebKeyStore
{

    private static List<KeyMaterial> _store = new();
    private SemaphoreSlim Slim = new(1);
    public Task Store(KeyMaterial keyMaterial)
    {
        Slim.Wait();
        _store.Add(keyMaterial);
        Slim.Release();

        return Task.CompletedTask;
    }

    public Task<KeyMaterial?> GetCurrent()
    {
        return Task.FromResult(_store.OrderByDescending(s => s.CreationDate).FirstOrDefault());
    }

    public async Task Revoke(KeyMaterial? keyMaterial)
    {
        if(keyMaterial == null)
            return;

        keyMaterial.Revoke();
        var oldOne = _store.Find(f => f.Id == keyMaterial.Id);
        if (oldOne != null)
        {
            var index = _store.FindIndex(f => f.Id == keyMaterial.Id);
            await Slim.WaitAsync();
            _store.RemoveAt(index);
            _store.Insert(index, keyMaterial);
            Slim.Release();
        }
    }

    public Task<ReadOnlyCollection<KeyMaterial>> GetLastKeys(int quantity)
    {
        return Task.FromResult(
            _store
                .OrderByDescending(s => s.CreationDate)
                .Take(quantity).ToList().AsReadOnly());
    }

    public Task<KeyMaterial>? Get(string keyId)
    {
        return Task.FromResult(_store.FirstOrDefault(w => w.KeyId == keyId));
    }

    public Task Clear()
    {
        _store.Clear();
        return Task.CompletedTask;
    }
}