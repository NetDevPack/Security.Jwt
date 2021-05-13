using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Win32;
using NetDevPack.Security.JwtSigningCredentials;
using NetDevPack.Security.JwtSigningCredentials.Interfaces;
using NetDevPack.Security.JwtSigningCredentials.Model;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Xml.Linq;
using System.Xml.Serialization;

namespace NetDevPack.Security.Jwt.Store.DataProtection
{
    public class AspNetCoreDataProtection : IJsonWebKeyStore
    {
        // Used for serializing elements to persistent storage
        internal static readonly XName IdAttributeName = "id";
        internal static readonly XName VersionAttributeName = "version";
        internal static readonly XName CreationDateElementName = "creationDate";
        internal static readonly XName ActivationDateElementName = "activationDate";
        internal static readonly XName ExpirationDateElementName = "expirationDate";
        internal static readonly XName DescriptorElementName = "descriptor";
        internal static readonly XName DeserializerTypeAttributeName = "deserializerType";
        internal static readonly XName RevocationElementName = "revocation";
        internal static readonly XName RevocationDateElementName = "revocationDate";
        internal static readonly XName ReasonElementName = "reason";

        private readonly ILoggerFactory _loggerFactory;
        private readonly IOptions<JwksOptions> _options;
        private readonly IAuthenticatedEncryptorDescriptorDeserializer _descriptorDeserializer;
        private IXmlRepository KeyRepository { get; set; }
        private IXmlEncryptor KeyEncryptor { get; set; }
        public IXmlDecryptor KeyDecryptor { get; set; }

        private const string Name = "NetDevPackSecurityJwt";
        public AspNetCoreDataProtection(ILoggerFactory loggerFactory, IOptions<JwksOptions> options, IAuthenticatedEncryptorDescriptorDeserializer descriptorDeserializer)
        {

            _loggerFactory = loggerFactory;
            _options = options;
            _descriptorDeserializer = descriptorDeserializer;
            Check();
            // Force it to configure xml repository.
        }
        public void Save(SecurityKeyWithPrivate securityParamteres)
        {
            var ser = new XmlSerializer(typeof(SecurityKeyWithPrivate));
            var doc = new XDocument();
            using (var xw = doc.CreateWriter())
            {
                ser.Serialize(xw, securityParamteres);
                xw.Close();
            }
            var possiblyEncryptedKeyElement = KeyEncryptor?.Encrypt(doc.Root) != null ? KeyEncryptor.Encrypt(doc.Root).EncryptedElement : doc.Root;

            // build the <key> element
            var keyElement = new XElement(Name,
                new XAttribute(IdAttributeName, securityParamteres.Id),
                new XAttribute(VersionAttributeName, 1),
                new XElement(CreationDateElementName, DateTimeOffset.Now),
                new XElement(ActivationDateElementName, DateTimeOffset.Now),
                new XElement(ExpirationDateElementName, DateTimeOffset.Now.AddDays(_options.Value.DaysUntilExpire)),
                new XElement(DescriptorElementName,
                    new XAttribute(DeserializerTypeAttributeName, typeof(SecurityKeyWithPrivate).AssemblyQualifiedName!),
                    possiblyEncryptedKeyElement));

            // Persist it to the underlying repository and trigger the cancellation token.
            var friendlyName = string.Format(CultureInfo.InvariantCulture, "key-{0}-{1:D}", securityParamteres.JwkType.ToString(), securityParamteres.KeyId);
            KeyRepository.StoreElement(keyElement, friendlyName);

        }

        private void Check()
        {
            if (KeyRepository == null)
            {
                (KeyRepository, KeyEncryptor, KeyDecryptor) = GetFallbackKeyRepositoryEncryptorPair();
            }
        }



        public SecurityKeyWithPrivate GetCurrentKey(JsonWebKeyType jwkType)
        {
            return GetKeys().FirstOrDefault(f => f.JwkType == jwkType);
        }

        private IOrderedEnumerable<SecurityKeyWithPrivate> GetKeys()
        {

            var allElements = KeyRepository.GetAllElements();
            var keys = new List<SecurityKeyWithPrivate>();
            foreach (var element in allElements)
            {
                if (element.Name == Name)
                {
                    var descriptorElement = element.Element(DescriptorElementName);
                    string descriptorDeserializerTypeName = (string)descriptorElement!.Attribute(DeserializerTypeAttributeName)!;
                    // Decrypt the descriptor element and pass it to the descriptor for consumption
                    var unencryptedInputToDeserializer = KeyDecryptor.Decrypt(descriptorElement)

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








        internal (IXmlRepository, IXmlEncryptor, IXmlDecryptor) GetFallbackKeyRepositoryEncryptorPair()
        {
            IXmlEncryptor xmlEncryptor = null;
            IXmlDecryptor xmlDecryptor = null;
            IXmlRepository key;
            DirectoryInfo forAzureWebSites = DefaultKeyStorageDirectories.Instance.GetKeyStorageDirectoryForAzureWebSites();
            if (forAzureWebSites != null)
            {
                key = (IXmlRepository)new FileSystemXmlRepository(forAzureWebSites, this._loggerFactory);
            }
            else
            {
                DirectoryInfo storageDirectory = DefaultKeyStorageDirectories.Instance.GetKeyStorageDirectory();
                if (storageDirectory != null)
                {
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        xmlEncryptor = new DpapiXmlEncryptor(false, this._loggerFactory);
                        xmlDecryptor = new DpapiXmlDecryptor();
                    }
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
                        xmlEncryptor = new DpapiXmlEncryptor(true, this._loggerFactory);
                        xmlDecryptor = new DpapiXmlDecryptor();
                        key = new RegistryXmlRepository(defaultRegistryKey, this._loggerFactory);
                    }
                    else
                    {
                        throw new Exception(
                            "Is not possible to determine which folder are the protection keys. NetDevPack.Security.JwtSigningCredentials.Store.FileSystem or NetDevPack.Security.JwtSigningCredentials.Store.EntityFrameworkCore");
                    }
                }
            }
            return (key, xmlEncryptor, xmlDecryptor);
        }


    }


}
