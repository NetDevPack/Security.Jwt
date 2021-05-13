using Microsoft.AspNetCore.DataProtection.KeyManagement.Internal;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Win32;
using NetDevPack.Security.JwtSigningCredentials;
using NetDevPack.Security.JwtSigningCredentials.Interfaces;
using NetDevPack.Security.JwtSigningCredentials.Model;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Xml.Linq;
using System.Xml.Serialization;

namespace NetDevPack.Security.Jwt.Store.DataProtection
{
    public class AspNetCoreDataProtection : IJsonWebKeyStore
    {
        private readonly IInternalXmlKeyManager _internalXmlKeyManager;
        private readonly IXmlRepository _xmlRepository;
        private const string Name = "NetDevPack.Security.Jwt";
        public AspNetCoreDataProtection(IInternalXmlKeyManager internalXmlKeyManager, IXmlRepository xmlRepository)
        {
            _internalXmlKeyManager = internalXmlKeyManager;
            _xmlRepository = xmlRepository;
            // Force it to configure xml repository.
        }
        public void Save(SecurityKeyWithPrivate securityParamteres)
        {
            using var memoryStream = new MemoryStream();
            using TextWriter streamWriter = new StreamWriter(memoryStream);

            var xmlSerializer = new XmlSerializer(typeof(SecurityKeyWithPrivate));
            xmlSerializer.Serialize(streamWriter, securityParamteres);
            _xmlRepository.Value.XmlRepository.StoreElement(XElement.Parse(Encoding.ASCII.GetString(memoryStream.ToArray())), Name);
        }

        public SecurityKeyWithPrivate GetCurrentKey(JsonWebKeyType jwkType)
        {
            return GetKeys().FirstOrDefault(f => f.JwkType == jwkType);
        }

        private IOrderedEnumerable<SecurityKeyWithPrivate> GetKeys()
        {

            var allElements = _xmlRepository.Value.XmlRepository.GetAllElements();
            var keys = new List<SecurityKeyWithPrivate>();
            foreach (var element in allElements)
            {
                if (element.Name == Name)
                {
                    var key = FromXElement<SecurityKeyWithPrivate>(element);
                    keys.Add(key);
                }
            }

            return keys.OrderByDescending(o => o.CreationDate);
        }

        private static T FromXElement<T>(XElement xElement)
        {
            var xmlSerializer = new XmlSerializer(typeof(T));
            return (T)xmlSerializer.Deserialize(xElement.CreateReader());
        }

        public IEnumerable<SecurityKeyWithPrivate> Get(JsonWebKeyType jwkType, int quantity = 5)
        {
            return GetKeys().Where(w => w.JwkType == jwkType).Take(quantity);
        }

        public void Clear()
        {

        }

        public bool NeedsUpdate(JsonWebKeyType jsonWebKeyType)
        {
            return true;
        }

        public void Update(SecurityKeyWithPrivate securityKeyWithPrivate)
        {
            throw new NotImplementedException();
        }












        internal KeyValuePair<IXmlRepository, IXmlEncryptor?> GetFallbackKeyRepositoryEncryptorPair()
        {
            IXmlRepository? repository = null;
            IXmlEncryptor? encryptor = null;

            // If we're running in Azure Web Sites, the key repository goes in the %HOME% directory.
            var azureWebSitesKeysFolder = _keyStorageDirectories.GetKeyStorageDirectoryForAzureWebSites();
            if (azureWebSitesKeysFolder != null)
            {
                _logger.UsingAzureAsKeyRepository(azureWebSitesKeysFolder.FullName);

                // Cloud DPAPI isn't yet available, so we don't encrypt keys at rest.
                // This isn't all that different than what Azure Web Sites does today, and we can always add this later.
                repository = new FileSystemXmlRepository(azureWebSitesKeysFolder, _loggerFactory);
            }
            else
            {
                // If the user profile is available, store keys in the user profile directory.
                var localAppDataKeysFolder = _keyStorageDirectories.GetKeyStorageDirectory();
                if (localAppDataKeysFolder != null)
                {
                    if (OSVersionUtil.IsWindows())
                    {
                        Debug.Assert(RuntimeInformation.IsOSPlatform(OSPlatform.Windows)); // Hint for the platform compatibility analyzer.

                        // If the user profile is available, we can protect using DPAPI.
                        // Probe to see if protecting to local user is available, and use it as the default if so.
                        encryptor = new DpapiXmlEncryptor(
                            protectToLocalMachine: !DpapiSecretSerializerHelper.CanProtectToCurrentUserAccount(),
                            loggerFactory: _loggerFactory);
                    }
                    repository = new FileSystemXmlRepository(localAppDataKeysFolder, _loggerFactory);

                    if (encryptor != null)
                    {
                        _logger.UsingProfileAsKeyRepositoryWithDPAPI(localAppDataKeysFolder.FullName);
                    }
                    else
                    {
                        _logger.UsingProfileAsKeyRepository(localAppDataKeysFolder.FullName);
                    }
                }
                else
                {
                    // Use profile isn't available - can we use the HKLM registry?
                    RegistryKey? regKeyStorageKey = null;
                    if (OSVersionUtil.IsWindows())
                    {
                        Debug.Assert(RuntimeInformation.IsOSPlatform(OSPlatform.Windows)); // Hint for the platform compatibility analyzer.
                        regKeyStorageKey = RegistryXmlRepository.DefaultRegistryKey;
                    }
                    if (regKeyStorageKey != null)
                    {
                        Debug.Assert(RuntimeInformation.IsOSPlatform(OSPlatform.Windows)); // Hint for the platform compatibility analyzer.
                        regKeyStorageKey = RegistryXmlRepository.DefaultRegistryKey;

                        // If the user profile isn't available, we can protect using DPAPI (to machine).
                        encryptor = new DpapiXmlEncryptor(protectToLocalMachine: true, loggerFactory: _loggerFactory);
                        repository = new RegistryXmlRepository(regKeyStorageKey!, _loggerFactory);

                        _logger.UsingRegistryAsKeyRepositoryWithDPAPI(regKeyStorageKey!.Name);
                    }
                    else
                    {
                        // Final fallback - use an ephemeral repository since we don't know where else to go.
                        // This can only be used for development scenarios.
                        repository = new EphemeralXmlRepository(_loggerFactory);

                        _logger.UsingEphemeralKeyRepository();
                    }
                }
            }

            return new KeyValuePair<IXmlRepository, IXmlEncryptor?>(repository, encryptor);
        }
    }
}
