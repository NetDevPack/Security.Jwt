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
            var current = await _store.GetCurrent(jwtKeyType, bypassCache: true);
            // if current is null, get the highest version ever created (manually revoked/first-run)
            current ??= (await _store.GetLastKeys(1, jwtKeyType)).FirstOrDefault();
            return await GenerateKey(jwtKeyType, current);
        }

        private async Task<SecurityKey> GenerateKey(JwtKeyType jwtKeyType, KeyMaterial previous)
        {
            var key = new CryptographicKey(jwtKeyType == JwtKeyType.Jws ? _options.Value.Jws : _options.Value.Jwe);

            var model = new KeyMaterial(key);
            // Next rotation version. Seeded at 1 on cold start and for pre-column rows (Version defaults to 0).
            model.Version = (previous?.Version ?? 0) + 1;
            // Store returns the persisted key when it wins the insert, or the key another replica already stored
            // for this version, so we never sign with a key that isn't published.
            var persisted = await _store.Store(model);

            return persisted.GetSecurityKey();
        }

        public async Task<SecurityKey> GetCurrentSecurityKey(JwtKeyType jwtKeyType = JwtKeyType.Jws)
        {
            var current = await _store.GetCurrent(jwtKeyType);

            if (NeedsUpdate(current))
            {
                await RotationLock.WaitAsync();
                try
                {
                    // Re-check under the lock, bypassing the cache
                    current = await _store.GetCurrent(jwtKeyType, bypassCache: true);
                    // No active key: fall back to the newest key including revoked. 
                    current ??= (await _store.GetLastKeys(1, jwtKeyType)).FirstOrDefault();
                    if (NeedsUpdate(current))
                    {
                        // According NIST - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf - Private key should be removed when no longer needs
                        await _store.Revoke(current);
                        return await GenerateKey(jwtKeyType, current);
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
            return _store.GetLastKeys(_options.Value.AlgorithmsToKeep, null);
        }

        public Task<ReadOnlyCollection<KeyMaterial>> GetLastKeys(int i, JwtKeyType jwtKeyType)
        {
            return _store.GetLastKeys(_options.Value.AlgorithmsToKeep, jwtKeyType);
        }

        private async Task<bool> CheckCompatibility(KeyMaterial currentKey, JwtKeyType jwtKeyType)
        {
            if (jwtKeyType == JwtKeyType.Jws && currentKey.Type != _options.Value.Jws.Kty()
                || jwtKeyType == JwtKeyType.Jwe && currentKey.Type != _options.Value.Jwe.Kty())
            {
                await GenerateKey(jwtKeyType, currentKey);
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
            var oldCurrent = await _store.GetCurrent(jwtKeyType, bypassCache: true);
            // if current is null, get the highest version ever created (manually revoked/first-run)
            oldCurrent ??= (await _store.GetLastKeys(1, jwtKeyType)).FirstOrDefault();
            await _store.Revoke(oldCurrent);
            return await GenerateKey(jwtKeyType, oldCurrent);
        }

        private bool NeedsUpdate(KeyMaterial current)
        {
            return current == null || current.IsExpired(_options.Value.DaysUntilExpire) || current.IsRevoked;
        }


    }
}
