using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using System.Collections.ObjectModel;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetDevPack.Security.Jwt.Core;
using NetDevPack.Security.Jwt.Core.Interfaces;
using NetDevPack.Security.Jwt.Core.Model;
using NetDevPack.Security.Jwt.Core.Jwa;

namespace NetDevPack.Security.Jwt.Store.FileSystem
{
    public class FileSystemStore : IJsonWebKeyStore
    {
        private readonly IOptions<JwtOptions> _options;
        private readonly IMemoryCache _memoryCache;
        public DirectoryInfo KeysPath { get; }

        public FileSystemStore(DirectoryInfo keysPath, IOptions<JwtOptions> options, IMemoryCache memoryCache)
        {
            _options = options;
            _memoryCache = memoryCache;
            KeysPath = keysPath;
            if (!KeysPath.Exists)
                KeysPath.Create();
        }

        private string GetCurrentFile()
        {
            var files = Directory.GetFiles(KeysPath.FullName, $"*current*.key");
            if (files.Any())
                return Path.Combine(KeysPath.FullName, files.First());

            return Path.Combine(KeysPath.FullName, $"{_options.Value.KeyPrefix}current.key");
        }

        public async Task Store(KeyMaterial securityParamteres)
        {
            if (!KeysPath.Exists)
                KeysPath.Create();

            // Datetime it's just to be easy searchable.
            if (File.Exists(GetCurrentFile()))
                File.Copy(GetCurrentFile(), Path.Combine(KeysPath.FullName, $"{_options.Value.KeyPrefix}old-{DateTime.Now:yyyy-MM-dd}-{securityParamteres.KeyId}.key"));

            await File.WriteAllTextAsync(Path.Combine(KeysPath.FullName, $"{_options.Value.KeyPrefix}current-{securityParamteres.KeyId}.key"), JsonSerializer.Serialize(securityParamteres, new JsonSerializerOptions() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull }));
            ClearCache();
        }

        public bool NeedsUpdate()
        {
            return !File.Exists(GetCurrentFile()) || File.GetCreationTimeUtc(GetCurrentFile()).AddDays(_options.Value.DaysUntilExpire) < DateTime.UtcNow.Date;
        }

        public async Task Revoke(KeyMaterial securityKeyWithPrivate, string reason = null)
        {
            if (securityKeyWithPrivate == null)
                return;

            securityKeyWithPrivate?.Revoke();
            foreach (var fileInfo in KeysPath.GetFiles("*.key"))
            {
                var key = GetKey(fileInfo.FullName);
                if (key.Id != securityKeyWithPrivate?.Id) continue;
                await File.WriteAllTextAsync(fileInfo.FullName, JsonSerializer.Serialize(securityKeyWithPrivate, new JsonSerializerOptions() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull }));
                break;
            }
            ClearCache();
        }


        public Task<KeyMaterial?> GetCurrent(JwtKeyType jwtKeyType = JwtKeyType.Jws)
        {
            var cacheKey = JwkContants.CurrentJwkCache + jwtKeyType;

            if (!_memoryCache.TryGetValue(cacheKey, out KeyMaterial credentials))
            {
                credentials = GetKey(GetCurrentFile());
                // Set cache options.
                var cacheEntryOptions = new MemoryCacheEntryOptions()
                    // Keep in cache for this time, reset time if accessed.
                    .SetSlidingExpiration(_options.Value.CacheTime);
                if (credentials != null)
                    _memoryCache.Set(cacheKey, credentials, cacheEntryOptions);
            }

            return Task.FromResult(credentials);
        }

        private KeyMaterial GetKey(string file)
        {
            if (!File.Exists(file)) throw new FileNotFoundException("Check configuration - cannot find auth key file: " + file);
            var keyParams = JsonSerializer.Deserialize<KeyMaterial>(File.ReadAllText(file));
            return keyParams!;

        }

        public Task<ReadOnlyCollection<KeyMaterial>> GetLastKeys(int quantity = 5, JwtKeyType? jwtKeyType = null)
        {
            var cacheKey = JwkContants.JwksCache + jwtKeyType;

            if (!_memoryCache.TryGetValue(cacheKey, out IReadOnlyCollection<KeyMaterial> keys))
            {
                keys = KeysPath.GetFiles("*.key")
                    .Take(quantity)
                    .Select(s => s.FullName)
                    .Select(GetKey).ToList().AsReadOnly();

                // Set cache options.
                var cacheEntryOptions = new MemoryCacheEntryOptions()
                    // Keep in cache for this time, reset time if accessed.
                    .SetSlidingExpiration(_options.Value.CacheTime);

                if (keys.Any())
                    _memoryCache.Set(cacheKey, keys, cacheEntryOptions);
            }

            return Task.FromResult(keys.ToList().AsReadOnly());
        }

        public Task<KeyMaterial?> Get(string keyId)
        {
            var files = Directory.GetFiles(KeysPath.FullName, $"*{keyId}*.key");
            if (files.Any())
                return Task.FromResult(GetKey(files.First()))!;

            return Task.FromResult(null as KeyMaterial);
        }

        public Task Clear()
        {
            if (KeysPath.Exists)
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
                foreach (var fileInfo in KeysPath.GetFiles($"*.key"))
                {
                    fileInfo.Delete();
                }
            }

            return Task.CompletedTask;
        }


        private void ClearCache()
        {
            _memoryCache.Remove(JwkContants.JwksCache);
            _memoryCache.Remove(JwkContants.JwksCache + JwtKeyType.Jws);
            _memoryCache.Remove(JwkContants.JwksCache + JwtKeyType.Jwe);
            _memoryCache.Remove(JwkContants.CurrentJwkCache);
            _memoryCache.Remove(JwkContants.CurrentJwkCache + JwtKeyType.Jws);
            _memoryCache.Remove(JwkContants.CurrentJwkCache + JwtKeyType.Jwe);
        }
    }
}
