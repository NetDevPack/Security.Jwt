using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;

namespace NetDevPack.Security.Jwt.Model
{
    /// <summary>
    /// It represent a public JWK to expose at JWKS endpoint
    /// </summary>
    public class PublicJsonWebKey
    {
        public PublicJsonWebKey(JsonWebKey jsonWebKey)
        {
            KeyType = jsonWebKey.Kty;
            PublicKeyUse = jsonWebKey.Use ?? "sig";
            KeyId = jsonWebKey.Kid;
            Algorithm = jsonWebKey.Alg;
            if (jsonWebKey.KeyOps.Any())
                KeyOperations = jsonWebKey.KeyOps;
            if (jsonWebKey.X5c.Any())
                X509Chain = jsonWebKey.X5c;
            X509Url = jsonWebKey.X5u;
            X5tS256 = jsonWebKey.X5t;

            if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve)
            {
                CurveName = jsonWebKey.Crv;
                X = jsonWebKey.X;
                Y = jsonWebKey.Y;
            }

            if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.RSA)
            {
                Modulus = jsonWebKey.N;
                Exponent = jsonWebKey.E;
            }

            if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.Octet)
            {
                Key = jsonWebKey.K;
            }
        }

        /// <summary>
        /// The "kty" (key type) parameter identifies the cryptographic algorithm family used with the key, such as "RSA" or "EC".
        /// "kty" values should either be registered in the IANA "JSON Web Key Types"
        /// Use of this member is REQUIRED.
        /// </summary>
        [JsonPropertyName("kty")]
        public string KeyType { get; }

        /// <summary>
        /// The "use" (public key use) parameter identifies the intended use of the public key.
        /// The "use" parameter is employed to indicate whether a public key is used for encrypting data or verifying the signature on data.
        /// Values defined by this specification are:
        /// * "sig" (signature)
        /// * "enc" (encryption)
        /// Use of this member is OPTIONAL.
        /// </summary>
        [JsonPropertyName("use")]
        public string PublicKeyUse { get; private set; }

        /// <summary>
        /// The "key_ops" (key operations) parameter identifies the operation(s) for which the key is intended to be used.
        /// The "key_ops" parameter is intended for use cases in which public, private, or symmetric keys may be present.
        /// Its value is an array of key operation values.  Values defined by this specification are:
        /// o  "sign" (compute digital signature or MAC)
        /// o  "verify" (verify digital signature or MAC)
        /// o  "encrypt" (encrypt content)
        /// o  "decrypt" (decrypt content and validate decryption, if applicable)
        /// o  "wrapKey" (encrypt key)
        /// o  "unwrapKey" (decrypt key and validate decryption, if applicable)
        /// o  "deriveKey" (derive key)
        /// o  "deriveBits" (derive bits not to be used as a key)
        /// Use of this member is OPTIONAL.
        /// </summary>
        [JsonPropertyName("key_ops")]
        public IList<string> KeyOperations { get; }

        /// <summary>
        /// The "alg" (algorithm) parameter identifies the algorithm intended for use with the key.
        /// The values used should either be registered in the IANA "JSON Web Signature and Encryption Algorithms"
        /// registry established by [JWA] or be a value that contains a Collision-Resistant Name.
        /// The "alg" value is a case-sensitive ASCII string.
        /// Use of this member is OPTIONAL.
        /// </summary>
        [JsonPropertyName("alg")]
        public string Algorithm { get; }

        /// <summary>
        /// The "kid" (key ID) parameter is used to match a specific key.
        /// This is used, for instance, to choose among a set of keys within a JWK Set during key rollover.
        /// The structure of the "kid" value is unspecified.
        /// When "kid" values are used within a JWK Set, different keys within the JWK Set SHOULD use distinct "kid" values.
        /// (One example in which different keys might use the same "kid" value is if they have different "kty" (key type)
        /// values but are considered to be equivalent alternatives by the application using them.)
        /// The "kid" value is a case-sensitive string.
        /// Use of this member is OPTIONAL.
        /// </summary>
        [JsonPropertyName("kid")]
        public string KeyId { get; }

        /// <summary>
        /// The "x5u" (X.509 URL) parameter is a URI [RFC3986] that refers to a resource for an X.509 public key certificate or certificate chain [RFC5280].
        /// </summary>
        [JsonPropertyName("x5u")]
        public string X509Url { get; set; }

        /// <summary>
        /// The "x5c" (X.509 certificate chain) parameter contains a chain of one or more PKIX certificates[RFC5280].
        /// </summary>
        [JsonPropertyName("x5c")]
        public IList<string> X509Chain { get; set; }

        /// <summary>
        /// The "x5t" (X.509 certificate SHA-1 thumbprint) parameter is a base64url-encoded SHA-1 thumbprint(a.k.a.digest) of the DER encoding of an X.509 certificate[RFC5280].
        /// </summary>
        [JsonPropertyName("x5t")]
        public string X5tS256 { get; set; }

        /// <summary>
        /// The "crv" (curve) parameter identifies the cryptographic curve used with the key.
        /// Curve values from [DSS] used by this specification are:
        ///   o  "P-256"
        ///   o  "P-384"
        ///   o  "P-521"
        /// </summary>
        [JsonPropertyName("crv")]
        public string CurveName { get; }

        /// <summary>
        /// The "x" (x coordinate) parameter contains the x coordinate for the
        /// Elliptic Curve point.  It is represented as the base64url encoding of
        /// the octet string representation of the coordinate, as defined in
        /// Section 2.3.5 of SEC1 [SEC1].  The length of this octet string MUST
        /// be the full size of a coordinate for the curve specified in the "crv"
        /// parameter.  For example, if the value of "crv" is "P-521", the octet
        /// string must be 66 octets long.
        /// </summary>
        [JsonPropertyName("x")]
        public string X { get; }

        /// <summary>
        /// The "y" (y coordinate) parameter contains the y coordinate for the
        /// Elliptic Curve point.  It is represented as the base64url encoding of
        /// the octet string representation of the coordinate, as defined in
        /// Section 2.3.5 of SEC1 [SEC1].  The length of this octet string MUST
        /// be the full size of a coordinate for the curve specified in the "crv"
        /// parameter.  For example, if the value of "crv" is "P-521", the octet
        /// string must be 66 octets long.
        /// </summary>
        [JsonPropertyName("y")]
        public string Y { get; }


        /// <summary>
        /// The "n" (modulus) parameter contains the modulus value for the RSA public key.
        /// It is represented as a Base64urlUInt-encoded value.
        /// </summary>
        [JsonPropertyName("n")]
        public string Modulus { get; set; }

        /// <summary>
        /// The "e" (exponent) parameter contains the exponent value for the RSA public key.
        /// It is represented as a Base64urlUInt-encoded value.
        /// </summary>
        [JsonPropertyName("e")]
        public string Exponent { get; set; }


        /// <summary>
        /// The "k" (key value) parameter contains the value of the symmetric (or other single-valued) key.
        /// It is represented as the base64url encoding of the octet sequence containing the key value.
        /// </summary>
        [JsonPropertyName("k")]
        public string Key { get; set; }


        public static PublicJsonWebKey FromJwk(JsonWebKey jwk)
        {
            return new PublicJsonWebKey(jwk);
        }

        public JsonWebKey ToNativeJwk()
        {
            var jsonWebKey = new JsonWebKey
            {
                Kty = KeyType,
                Use = PublicKeyUse,
                Kid = KeyId,
                Alg = Algorithm,
                X5u = X509Url,
                X5t = X5tS256,
                Crv = CurveName,
                X = X,
                Y = Y,
                N = Modulus,
                E = Exponent,
                K = Key
            };

            if (KeyOperations != null)
                foreach (var keyOperation in KeyOperations)
                    jsonWebKey.KeyOps.Add(keyOperation);

            if (X509Chain != null)
                foreach (var certificate in X509Chain)
                    jsonWebKey.X5c.Add(certificate);

            return jsonWebKey;
        }
    }
}
