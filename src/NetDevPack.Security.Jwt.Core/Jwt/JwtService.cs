using System.Collections.ObjectModel;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.Core.Interfaces;
using NetDevPack.Security.Jwt.Core.Model;

namespace NetDevPack.Security.Jwt.Core.Jwt
{
    internal class JwtService : IJwtService
    {
        private readonly IJsonWebKeyStore _store;
        private readonly IOptions<JwtOptions> _options;

        public JwtService(IJsonWebKeyStore store, IOptions<JwtOptions> options)
        {
            _store = store;
            _options = options;
        }
        public async Task<SecurityKey> GenerateKey()
        {
            var key = new CryptographicKey(_options.Value.Jws);

            var model = new KeyMaterial(key);
            await _store.Store(model);

            return model.GetSecurityKey();
        }

        public async Task<SecurityKey> GetCurrentSecurityKey()
        {
            var current = await _store.GetCurrent();

            if (NeedsUpdate(current))
            {
                // According NIST - https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf - Private key should be removed when no longer needs
                await _store.Revoke(current);
                var newKey = await GenerateKey();
                return newKey;
            }

            // options has change. Change current key
            if (!await CheckCompatibility(current))
                current = await _store.GetCurrent();

            return current;
        }
        public async Task<SigningCredentials> GetCurrentSigningCredentials()
        {
            var current = await GetCurrentSecurityKey();

            return new SigningCredentials(current, _options.Value.Jws);
        }

        public async Task<EncryptingCredentials> GetCurrentEncryptingCredentials()
        {
            var current = await GetCurrentSecurityKey();

            return new EncryptingCredentials(current, _options.Value.Jwe.Alg, _options.Value.Jwe.EncryptionAlgorithmContent);
        }

        public Task<ReadOnlyCollection<KeyMaterial>> GetLastKeys(int i)
        {
            return _store.GetLastKeys(5);
        }


        private async Task<bool> CheckCompatibility(KeyMaterial currentKey)
        {
            if (currentKey.Type != _options.Value.Jws.Kty())
            {
                await GenerateKey();
                return false;
            }
            return true;
        }

        private bool NeedsUpdate(KeyMaterial current)
        {
            return current == null || current.IsExpired(_options.Value.DaysUntilExpire);
        }


    }
}
