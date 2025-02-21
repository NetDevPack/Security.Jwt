using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
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

        public DatabaseJsonWebKeyStore(TContext context, ILogger<DatabaseJsonWebKeyStore<TContext>> logger, IOptions<JwtOptions> options, IMemoryCache memoryCache)
        {
            _context = context;
            _options = options;
            _memoryCache = memoryCache;
            _logger = logger;
        }

        public async Task Store(KeyMaterial securityParamteres)
        {
            await _context.SecurityKeys.AddAsync(securityParamteres);

            _logger.LogInformation($"Saving new SecurityKeyWithPrivate {securityParamteres.Id}", typeof(TContext).Name);
            await _context.SaveChangesAsync();
            ClearCache();
        }

        public async Task<KeyMaterial> GetCurrent(JwtKeyType jwtKeyType = JwtKeyType.Jws)
        {
            var cacheKey = JwkContants.CurrentJwkCache + jwtKeyType;

            if (!_memoryCache.TryGetValue(cacheKey, out KeyMaterial credentials))
            {
#if NET5_0_OR_GREATER
                credentials = await _context.SecurityKeys.Where(X => X.IsRevoked == false).OrderByDescending(d => d.CreationDate).AsNoTrackingWithIdentityResolution().FirstOrDefaultAsync();
#else
                credentials = await _context.SecurityKeys.Where(X => X.IsRevoked == false).OrderByDescending(d => d.CreationDate).AsNoTracking().FirstOrDefaultAsync();
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
                keys = _context.SecurityKeys.OrderByDescending(d => d.CreationDate).Take(quantity).AsNoTrackingWithIdentityResolution().ToList().AsReadOnly();
#else
                keys = _context.SecurityKeys.OrderByDescending(d => d.CreationDate).Take(quantity).AsNoTracking().ToList().AsReadOnly();
#endif
                // Set cache options.
                var cacheEntryOptions = new MemoryCacheEntryOptions()
                    // Keep in cache for this time, reset time if accessed.
                    .SetSlidingExpiration(_options.Value.CacheTime);

                if (keys.Any())
                    _memoryCache.Set(cacheKey, keys, cacheEntryOptions);

                return keys;
            }

            return keys;
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

            securityKeyWithPrivate.Revoke(reason);
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
