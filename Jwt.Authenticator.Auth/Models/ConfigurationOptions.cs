using System.Text;

namespace Jwt.Authenticator.Auth.Models
{
    public class ConfigurationOptions
    {
        public byte[]? Secret { get; }
        public int? ExpirationInSeconds { get; }
        public string? Issuer { get; }
        public string? Audience { get; }


        private ConfigurationOptions(string secret, int? expirationInSeconds, string issuer, string audience)
        {
            Secret = Encoding.UTF8.GetBytes(secret);
            ExpirationInSeconds = expirationInSeconds;
            Issuer = issuer;
            Audience = audience;
        }

        public static ConfigurationOptions Create(string secret, int? expirationInSeconds, string issuer, string audience)
        {
            return new ConfigurationOptions(secret, expirationInSeconds, issuer, audience);
        }
    }
}
