namespace Jwks.SigningCredentialsManager
{
    /// <summary>Output format for unique IDs</summary>
    internal enum OutputFormat
    {
        /// <summary>URL-safe Base64</summary>
        Base64Url,
        /// <summary>Base64</summary>
        Base64,
        /// <summary>Hex</summary>
        Hex,
    }
}