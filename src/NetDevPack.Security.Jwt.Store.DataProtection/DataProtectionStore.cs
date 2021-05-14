using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Win32;
using NetDevPack.Security.JwtSigningCredentials;
using NetDevPack.Security.JwtSigningCredentials.Interfaces;
using NetDevPack.Security.JwtSigningCredentials.Jwks;
using NetDevPack.Security.JwtSigningCredentials.Model;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Xml.Linq;

namespace NetDevPack.Security.Jwt.Store.DataProtection
{
    public class DataProtectionStore : IJsonWebKeyStore
    {
        // Used for serializing elements to persistent storage
        internal static readonly XName IdAttributeName = "id";
        internal static readonly XName VersionAttributeName = "version";
        internal static readonly XName CreationDateElementName = "creationDate";
        internal static readonly XName ActivationDateElementName = "activationDate";
        internal static readonly XName ExpirationDateElementName = "expirationDate";
        internal static readonly XName DescriptorElementName = "descriptor";
        internal static readonly XName DeserializerTypeAttributeName = "deserializerType";
        internal static readonly XName RevocationElementName = "NetDevPackSecurityJwtRevocation";
        internal static readonly XName RevocationDateElementName = "revocationDate";
        internal static readonly XName ReasonElementName = "reason";

        private readonly ILoggerFactory _loggerFactory;
        private readonly IOptions<JwksOptions> _options;
        private readonly IOptions<KeyManagementOptions> _keyManagementOptions;
        private readonly IMemoryCache _memoryCache;
        private readonly IDataProtector _dataProtector;

        private IXmlRepository KeyRepository { get; set; }

        private const string Name = "NetDevPackSecurityJwt";
        public DataProtectionStore(
            ILoggerFactory loggerFactory,
            IOptions<JwksOptions> options,
            IDataProtectionProvider provider,
            IOptions<KeyManagementOptions> keyManagementOptions,
            IMemoryCache memoryCache)
        {
            _loggerFactory = loggerFactory;
            _options = options;
            _keyManagementOptions = keyManagementOptions;
            _memoryCache = memoryCache;
            _dataProtector = provider.CreateProtector(typeof(SecurityKeyWithPrivate).AssemblyQualifiedName); ;
            Check();
            // Force it to configure xml repository.
        }
        public void Save(SecurityKeyWithPrivate securityParamteres)
        {
            var possiblyEncryptedKeyElement = _dataProtector.Protect(System.Text.Json.JsonSerializer.Serialize(securityParamteres));

            // build the <key> element
            var keyElement = new XElement(Name,
                new XAttribute(IdAttributeName, securityParamteres.Id),
                new XAttribute(VersionAttributeName, 1),
                new XElement(CreationDateElementName, DateTimeOffset.UtcNow),
                new XElement(ActivationDateElementName, DateTimeOffset.UtcNow),
                new XElement(ExpirationDateElementName, DateTimeOffset.UtcNow.AddDays(_options.Value.DaysUntilExpire)),
                new XElement(DescriptorElementName,
                    new XAttribute(DeserializerTypeAttributeName, typeof(SecurityKeyWithPrivate).AssemblyQualifiedName!),
                    possiblyEncryptedKeyElement));

            // Persist it to the underlying repository and trigger the cancellation token.
            var friendlyName = string.Format(CultureInfo.InvariantCulture, "key-{0}-{1:D}", securityParamteres.JwkType.ToString(), securityParamteres.Id);
            KeyRepository.StoreElement(keyElement, friendlyName);
            ClearCache();
        }

        private void Check()
        {
            KeyRepository = _keyManagementOptions.Value.XmlRepository;
            if (KeyRepository == null)
            {
                KeyRepository = GetFallbackKeyRepositoryEncryptorPair();
            }
        }



        public SecurityKeyWithPrivate GetCurrentKey(JsonWebKeyType jwkType)
        {
            if (!_memoryCache.TryGetValue(JwkContants.CurrentJwkCache(jwkType), out SecurityKeyWithPrivate credentials))
            {
                credentials = Get(jwkType, 1).FirstOrDefault();
                // Set cache options.
                var cacheEntryOptions = new MemoryCacheEntryOptions()
                    // Keep in cache for this time, reset time if accessed.
                    .SetSlidingExpiration(_options.Value.CacheTime);

                if (credentials != null)
                    _memoryCache.Set(JwkContants.CurrentJwkCache(jwkType), credentials, cacheEntryOptions);
            }

            return credentials;
        }

        private IReadOnlyCollection<SecurityKeyWithPrivate> GetKeys()
        {
            var allElements = KeyRepository.GetAllElements();
            var keys = new List<SecurityKeyWithPrivate>();
            var revokedKeys = new List<string>();
            foreach (var element in allElements)
            {
                if (element.Name == Name)
                {
                    var descriptorElement = element.Element(DescriptorElementName);
                    // Decrypt the descriptor element and pass it to the descriptor for consumption
                    var unencryptedInputToDeserializer = _dataProtector.Unprotect(descriptorElement.Value);
                    var key = JsonSerializer.Deserialize<SecurityKeyWithPrivate>(unencryptedInputToDeserializer);
                    // IXmlRepository doesn't allow us to update. So remove from Get to prevent errors
                    if (key.IsExpired(_options.Value.DaysUntilExpire))
                    {
                        Revoke(key);
                        revokedKeys.Add(key.Id.ToString());
                    }

                    keys.Add(key);
                }
                else if (element.Name == RevocationElementName)
                {
                    var keyIdAsString = (string)element.Element(Name)!.Attribute(IdAttributeName)!;
                    revokedKeys.Add(keyIdAsString);
                }
            }

            foreach (var revokedKey in revokedKeys)
            {
                keys.FirstOrDefault(a => a.Id.ToString().Equals(revokedKey))?.Revoke();
            }
            return keys.ToList();
        }


        public IReadOnlyCollection<SecurityKeyWithPrivate> Get(JsonWebKeyType jsonWebKeyType, int quantity = 5)
        {
            if (!_memoryCache.TryGetValue(JwkContants.JwksCache, out IReadOnlyCollection<SecurityKeyWithPrivate> keys))
            {
                keys = GetKeys();

                // Set cache options.
                var cacheEntryOptions = new MemoryCacheEntryOptions()
                    // Keep in cache for this time, reset time if accessed.
                    .SetSlidingExpiration(_options.Value.CacheTime);

                if (keys.Any())
                    _memoryCache.Set(JwkContants.JwksCache, keys, cacheEntryOptions);
            }

            return keys
                .Where(w => w.JwkType == jsonWebKeyType)
                .OrderByDescending(s => s.CreationDate)
                .ToList()
                .AsReadOnly();
        }

        public void Clear()
        {
            foreach (var securityKeyWithPrivate in GetKeys())
            {
                Revoke(securityKeyWithPrivate);
            }
        }

        public bool NeedsUpdate(JsonWebKeyType jsonWebKeyType)
        {
            var current = GetCurrentKey(jsonWebKeyType);
            if (current == null)
                return true;

            return current.CreationDate.AddDays(_options.Value.DaysUntilExpire) < DateTime.UtcNow.Date;
        }

        public void Revoke(SecurityKeyWithPrivate securityKeyWithPrivate)
        {
            var key = Get(securityKeyWithPrivate.JwkType).First(f => f.Id == securityKeyWithPrivate.Id);
            if (key != null && key.IsRevoked)
                return;

            securityKeyWithPrivate.Revoke();
            var revocationElement = new XElement(RevocationElementName,
                new XAttribute(VersionAttributeName, 1),
                new XElement(RevocationDateElementName, DateTimeOffset.UtcNow),
                new XElement(Name,
                    new XAttribute(IdAttributeName, securityKeyWithPrivate.Id)),
                new XElement(ReasonElementName, "Revoked"));


            // Persist it to the underlying repository and trigger the cancellation token
            var friendlyName = string.Format(CultureInfo.InvariantCulture, "revocation-{0}-{1:D}-{2:yyyy_MM_dd_hh_mm_fffffff}", securityKeyWithPrivate.JwkType.ToString(), securityKeyWithPrivate.Id, DateTime.UtcNow);
            KeyRepository.StoreElement(revocationElement, friendlyName);
            ClearCache();
        }


        private void ClearCache()
        {
            _memoryCache.Remove(JwkContants.JwksCache);
            _memoryCache.Remove(JwkContants.CurrentJwkCache(JsonWebKeyType.Jwe));
            _memoryCache.Remove(JwkContants.CurrentJwkCache(JsonWebKeyType.Jws));
        }

        /// <summary>
        /// https://github.com/dotnet/aspnetcore/blob/d8906c8523f071371ce95d4e2d2fdfa89858047e/src/DataProtection/DataProtection/src/KeyManagement/XmlKeyManager.cs#L105
        /// </summary>
        /// <returns></returns>
        internal IXmlRepository GetFallbackKeyRepositoryEncryptorPair()
        {
            IXmlRepository key;
            var forAzureWebSites = DefaultKeyStorageDirectories.Instance.GetKeyStorageDirectoryForAzureWebSites();
            if (forAzureWebSites != null)
            {
                key = new FileSystemXmlRepository(forAzureWebSites, this._loggerFactory);
            }
            else
            {
                var storageDirectory = DefaultKeyStorageDirectories.Instance.GetKeyStorageDirectory();
                if (storageDirectory != null)
                {
                    key = new FileSystemXmlRepository(storageDirectory, this._loggerFactory);
                }
                else
                {
                    RegistryKey registryKey = null;
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                        registryKey = RegistryXmlRepository.DefaultRegistryKey;

                    if (registryKey != null)
                    {
                        var defaultRegistryKey = RegistryXmlRepository.DefaultRegistryKey;
                        key = new RegistryXmlRepository(defaultRegistryKey, this._loggerFactory);
                    }
                    else
                    {
                        throw new Exception(
                            "Is not possible to determine which folder are the protection keys. NetDevPack.Security.JwtSigningCredentials.Store.FileSystem or NetDevPack.Security.JwtSigningCredentials.Store.EntityFrameworkCore");
                    }
                }
            }
            return key;
        }


    }


}
