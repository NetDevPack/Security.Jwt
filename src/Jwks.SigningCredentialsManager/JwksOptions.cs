using Microsoft.IdentityModel.Tokens;

namespace Jwks.SigningCredentialsManager
{
    public class JwksOptions
    {
        public KeyFormat Format { get; set; } = KeyFormat.RSA;
        public string Algorithm { get; set; } = SecurityAlgorithms.RsaSsaPssSha256;
        public int DaysUntilExpire { get; set; } = 90;
    }
}