using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetDevPack.Security.Jwt.Core;
using NetDevPack.Security.Jwt.Core.Interfaces;
using NetDevPack.Security.Jwt.Core.Jwa;
using NetDevPack.Security.Jwt.Core.Model;

namespace NetDevPack.Security.Jwt.Store.EntityFrameworkCore
{
    internal class DatabaseJsonWebKeyStore<TContext> : IJsonWebKeyStore
        where TContext : DbContext, ISecurityKeyContext
    {
        private readonly TContext _context;
        private readonly IOptions<JwtOptions> _options;
        private readonly IMemoryCache _memoryCache;
        private readonly ILogger<DatabaseJsonWebKeyStore<TContext>> _logger;
        internal const string DefaultRevocationReason = "Revoked";

        public DatabaseJsonWebKeyStore(TContext context, ILogger<DatabaseJsonWebKeyStore<TContext>> logger, IOptions<JwtOptions> options, IMemoryCache memoryCache)
        {
            _context = context;
            _options = options;
            _memoryCache = memoryCache;
            _logger = logger;
        }

        public async Task<KeyMaterial> Store(KeyMaterial securityParamteres)
        {
            // Deterministic Id per use + kty + rotation version
            // every replica replacing the same key computes the same Id
            // Concurrent inserts collide on the primary key
            securityParamteres.Id = DeterministicId(securityParamteres.Use, securityParamteres.Type, securityParamteres.Version);

            _logger.LogInformation($"Saving new SecurityKeyWithPrivate {securityParamteres.Id}", typeof(TContext).Name);
            try
            {
                await _context.SecurityKeys.AddAsync(securityParamteres);
                await _context.SaveChangesAsync();
            }
            catch
            {
                // Lost the race or a transient fault. 
                _context.Entry(securityParamteres).State = EntityState.Detached;
                var winner = await _context.SecurityKeys.AsNoTracking()
                    .FirstOrDefaultAsync(k => k.Id == securityParamteres.Id);
                if (winner == null)
                    throw;

                // Return the persisted winner so the caller signs with the published key, not our orphan.
                ClearCache();
                return winner;
            }
            ClearCache();
            return securityParamteres;
        }

        private static Guid DeterministicId(string use, string kty, long version)
        {
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(Encoding.UTF8.GetBytes($"{use}:{kty}:{version}"));
            var guidBytes = new byte[16];
            Array.Copy(hash, guidBytes, 16);
            return new Guid(guidBytes);
        }

        public async Task<KeyMaterial> GetCurrent(JwtKeyType jwtKeyType = JwtKeyType.Jws, bool bypassCache = false)
        {
            var cacheKey = JwkContants.CurrentJwkCache + jwtKeyType;

            if (bypassCache || !_memoryCache.TryGetValue(cacheKey, out KeyMaterial credentials))
            {
                var keyType = (jwtKeyType == JwtKeyType.Jws ? "sig" : "enc");
#if NET5_0_OR_GREATER
                credentials = await _context.SecurityKeys.Where(X => X.IsRevoked == false).Where(s => s.Use == keyType).OrderByDescending(d => d.CreationDate).AsNoTrackingWithIdentityResolution().FirstOrDefaultAsync();
#else
                credentials = await _context.SecurityKeys.Where(X => X.IsRevoked == false).Where(s => s.Use == keyType).OrderByDescending(d => d.CreationDate).AsNoTracking().FirstOrDefaultAsync();
#endif

                // Set cache options.
                var cacheEntryOptions = new MemoryCacheEntryOptions()
                    // Keep in cache for this time, reset time if accessed.
                    .SetSlidingExpiration(_options.Value.CacheTime);

                if (credentials != null)
                    _memoryCache.Set(cacheKey, credentials, cacheEntryOptions);

                return credentials;
            }

            return credentials;
        }

        public async Task<ReadOnlyCollection<KeyMaterial>> GetLastKeys(int quantity = 5, JwtKeyType? jwtKeyType = null)
        {
            var cacheKey = JwkContants.JwksCache + jwtKeyType;

            if (!_memoryCache.TryGetValue(cacheKey, out ReadOnlyCollection<KeyMaterial> keys))
            {
#if NET5_0_OR_GREATER
                keys = (await _context.SecurityKeys.Where(s => jwtKeyType == null || s.Use == (jwtKeyType == JwtKeyType.Jws ? "sig" : "enc"))
                                    .OrderByDescending(d => d.CreationDate).AsNoTrackingWithIdentityResolution().ToListAsync()).AsReadOnly();
#else
                keys = _context.SecurityKeys.Where(s => jwtKeyType == null || s.Use == (jwtKeyType == JwtKeyType.Jws ? "sig" : "enc"))
                                    .OrderByDescending(d => d.CreationDate).AsNoTracking().ToList().AsReadOnly();
#endif
                // Set cache options.
                var cacheEntryOptions = new MemoryCacheEntryOptions()
                    // Keep in cache for this time, reset time if accessed.
                    .SetSlidingExpiration(_options.Value.CacheTime);

                if (keys.Any())
                    _memoryCache.Set(cacheKey, keys, cacheEntryOptions);
            }

            return keys.GroupBy(s => s.Use)
                        .SelectMany(g => g.Take(quantity))
                        .ToList().AsReadOnly();
        }

        public Task<KeyMaterial> Get(string keyId)
        {
            return _context.SecurityKeys.FirstOrDefaultAsync(f => f.KeyId == keyId);
        }

        public async Task Clear()
        {
            foreach (var securityKeyWithPrivate in _context.SecurityKeys)
            {
                _context.SecurityKeys.Remove(securityKeyWithPrivate);
            }

            await _context.SaveChangesAsync();
            ClearCache();
        }


        public async Task Revoke(KeyMaterial securityKeyWithPrivate, string reason = null)
        {
            if (securityKeyWithPrivate == null)
                return;

            securityKeyWithPrivate.Revoke(reason ?? DefaultRevocationReason);
            _context.Attach(securityKeyWithPrivate);
            _context.SecurityKeys.Update(securityKeyWithPrivate);
            await _context.SaveChangesAsync();
            ClearCache();
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
