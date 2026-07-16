using System.Collections.ObjectModel;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Core.Interfaces;
using NetDevPack.Security.Jwt.Core.Jwa;
using NetDevPack.Security.Jwt.Core.Model;

namespace NetDevPack.Security.Jwt.Core.Jwt
{
    internal class JwtService : IJwtService
    {
        private readonly IJsonWebKeyStore _store;
        private readonly IOptions<JwtOptions> _options;
        // Process-wide lock so a scoped service across concurrent requests rotates once, not once per request.
        private static readonly SemaphoreSlim RotationLock = new(1, 1);

        public JwtService(IJsonWebKeyStore store, IOptions<JwtOptions> options)
        {
            _store = store;
            _options = options;
        }
        public async Task<SecurityKey> GenerateKey(JwtKeyType jwtKeyType = JwtKeyType.Jws)
        {
            async Task<KeyMaterial> StoreNewKey()
            {
                var key = new CryptographicKey(jwtKeyType == JwtKeyType.Jws ? _options.Value.Jws : _options.Value.Jwe);
                await _store.Store(new KeyMaterial(key));
                return await _store.GetCurrent(jwtKeyType);
            }

            var current = await StoreNewKey();

            // If current is null, the last stored key was also revoked during the race
            current ??= await StoreNewKey();

            // A second null means keys are being revoked as fast as we mint them
            return current?.GetSecurityKey()
                   ?? throw new InvalidOperationException($"Unable to persist an active {jwtKeyType} key: keys are being revoked concurrently.");
        }

        public async Task<SecurityKey> GetCurrentSecurityKey(JwtKeyType jwtKeyType = JwtKeyType.Jws)
        {
            var current = await _store.GetCurrent(jwtKeyType);

            if (NeedsUpdate(current))
            {
                await RotationLock.WaitAsync();
                try
                {
                    // Re-check: if another request on this pod already rotated, its Store cleared the cache
                    // and this read comes back fresh.
                    current = await _store.GetCurrent(jwtKeyType);
                    if (NeedsUpdate(current))
                    {
                        // According NIST - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf - Private key should be removed when no longer needs
                        await _store.Revoke(current);
                        // All stores would internally clear cache on revoke
                        // So this GetCurrent is from the actual source, and could possibly be updated by someone else.
                        current = await _store.GetCurrent(jwtKeyType);
                        if (NeedsUpdate(current))
                            return await GenerateKey(jwtKeyType);
                    }
                }
                finally
                {
                    RotationLock.Release();
                }
            }

            // options has change. Change current key
            if (!await CheckCompatibility(current, jwtKeyType))
                current = await _store.GetCurrent(jwtKeyType);

            return current;
        }
        public async Task<SigningCredentials> GetCurrentSigningCredentials()
        {
            var current = await GetCurrentSecurityKey(JwtKeyType.Jws);

            return new SigningCredentials(current, _options.Value.Jws);
        }

        public async Task<EncryptingCredentials> GetCurrentEncryptingCredentials()
        {
            var current = await GetCurrentSecurityKey(JwtKeyType.Jwe);

            return new EncryptingCredentials(current, _options.Value.Jwe.Alg, _options.Value.Jwe.EncryptionAlgorithmContent);
        }

        public Task<ReadOnlyCollection<KeyMaterial>> GetLastKeys(int? i = null)
        {
            return _store.GetLastKeys(i ?? _options.Value.AlgorithmsToKeep, null);
        }

        public Task<ReadOnlyCollection<KeyMaterial>> GetLastKeys(int i, JwtKeyType jwtKeyType)
        {
            return _store.GetLastKeys(i, jwtKeyType);
        }

        private async Task<bool> CheckCompatibility(KeyMaterial currentKey, JwtKeyType jwtKeyType)
        {
            if (jwtKeyType == JwtKeyType.Jws && currentKey.Type != _options.Value.Jws.Kty()
                || jwtKeyType == JwtKeyType.Jwe && currentKey.Type != _options.Value.Jwe.Kty())
            {
                await GenerateKey(jwtKeyType);
                return false;
            }
            return true;
        }

        public async Task RevokeKey(string keyId, string reason = null)
        {
            var key = await _store.Get(keyId);

            await _store.Revoke(key, reason);
        }

        public async Task<SecurityKey> GenerateNewKey(JwtKeyType jwtKeyType = JwtKeyType.Jws)
        {
            var oldCurrent = await _store.GetCurrent(jwtKeyType);
            await _store.Revoke(oldCurrent);
            return await GenerateKey(jwtKeyType);
        }

        private bool NeedsUpdate(KeyMaterial current)
        {
            return current == null || current.IsExpired(_options.Value.DaysUntilExpire) || current.IsRevoked;
        }


    }
}
