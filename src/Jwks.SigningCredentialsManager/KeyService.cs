using Jwks.SigningCredentialsManager.Store;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Jwks.SigningCredentialsManager
{
    /// <summary>
    /// Util class to allow restoring RSA/ECDsa parameters from JSON as the normal
    /// parameters class won't restore private key info.
    /// </summary>
    public class KeyService : IKeyService
    {
        private readonly IKeyStore _store;
        private readonly IOptions<JwksOptions> _options;

        public KeyService(IKeyStore store, IOptions<JwksOptions> options)
        {
            _store = store;
            _options = options;
        }

        private SigningCredentials GenerateRsa(string algorithms = SecurityAlgorithms.RsaSsaPssSha256)
        {
            var key = CryptoService.CreateRsaSecurityKey();
            var t = new SecurityKeyWithPrivate();
            t.SetParameters(key, algorithms);
            _store.Save(t);
            return new SigningCredentials(key, algorithms);
        }
        private SigningCredentials GenerateECDsa(string algorithms = SecurityAlgorithms.EcdsaSha256)
        {
            var key = CryptoService.CreateECDsaSecurityKey();
            var t = new SecurityKeyWithPrivate();
            t.SetParameters(key, algorithms);
            _store.Save(t);
            return new SigningCredentials(key, algorithms);
        }

        public SigningCredentials Generate()
        {
            return _options.Value.Format switch
            {
                KeyFormat.RSA => GenerateRsa(_options.Value.Algorithm),
                KeyFormat.ECDsa => GenerateECDsa(_options.Value.Algorithm),
                _ => throw new ArgumentOutOfRangeException(nameof(_options.Value.Format), _options.Value.Format, null)
            };
        }

        /// <summary>
        /// If current doesn't exist will generate new one
        /// </summary>
        public SigningCredentials GetCurrent()
        {
            if (_store.NeedsUpdate())
                return Generate();

            var securityFile = _store.GetCurrentKey();
            return new SigningCredentials(GetSecurityKey(securityFile), securityFile.Algorithm);
        }

        public IReadOnlyCollection<SecurityKeyWithPrivate> GetLastKeysCredentials(int qty)
        {
            return _store.Get(qty);
        }

        public SecurityKey GetSecurityKey(SecurityKeyWithPrivate securityFile)
        {
            SecurityKey asymmetric;
            if (securityFile.Type == typeof(RsaSecurityKey).Name)
            {
                var rsaParameters = JsonConvert.DeserializeObject<RSAParameters>(securityFile.Parameters);
                asymmetric = new RsaSecurityKey(rsaParameters)
                {
                    KeyId = securityFile.KeyId
                };
            }
            else
            {
                var ecdsaParameters = JsonConvert.DeserializeObject<ECParameters>(securityFile.Parameters);
                asymmetric = new ECDsaSecurityKey(ECDsa.Create(ecdsaParameters))
                {
                    KeyId = securityFile.KeyId
                };
            }

            return asymmetric;
        }
    }
}