using System;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace Jwks.SigningCredentialsManager
{

    /// <summary>
    /// This points to a JSON file in the format: 
    /// {
    ///  "Modulus": "",
    ///  "Exponent": "",
    ///  "P": "",
    ///  "Q": "",
    ///  "DP": "",
    ///  "DQ": "",
    ///  "InverseQ": "",
    ///  "D": ""
    /// }
    /// </summary>
    public class SecurityKeyWithPrivate
    {
        public Guid Id { get; set; }
        public string Parameters { get; set; }
        public string KeyId { get; set; }
        public string Type { get; set; }
        public string Algorithm { get; set; }
        public DateTime CreationDate { get; set; }

        public void SetParameters(ECDsaSecurityKey key, string alg)
        {
            Type = typeof(ECDsaSecurityKey).Name;
            Parameters = JsonConvert.SerializeObject(key.ECDsa.ExportParameters(includePrivateParameters: true));
            KeyId = key.KeyId;
            Algorithm = alg;
            CreationDate = DateTime.Now;
        }
        public void SetParameters(RsaSecurityKey key, string alg)
        {
            Type = typeof(RsaSecurityKey).Name;
            Parameters = JsonConvert.SerializeObject(key.Rsa.ExportParameters(includePrivateParameters: true));
            KeyId = key.KeyId;
            Algorithm = alg;
            CreationDate = DateTime.Now;
        }
    }
}