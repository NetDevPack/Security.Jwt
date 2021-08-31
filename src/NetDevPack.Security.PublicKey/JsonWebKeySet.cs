using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace NetDevPack.Security.PublicKey
{
    /// <summary>
    /// Helper class to get jwks
    /// </summary>
    public class JsonWebKeySet
    {
        [JsonPropertyName("keys")]
        public IEnumerable<PublicJsonWebKey> Keys { get; set; }
    }
}