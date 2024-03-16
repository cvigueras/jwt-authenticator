using System.Text;

namespace Jwt.Authenticator.Auth.Models
{
    public class ConfigurationOptions
    {
        public byte[]? Key { get; }
        public int? ExpirationInSeconds { get; }
        public string? Issuer { get; }
        public string? Audience { get; }


        private ConfigurationOptions(string key, int? expirationInSeconds, string issuer, string audience)
        {
            Key = Encoding.UTF8.GetBytes(key);
            ExpirationInSeconds = expirationInSeconds;
            Issuer = issuer;
            Audience = audience;
        }

        public static ConfigurationOptions Create(string key, int? expirationInSeconds, string issuer, string audience)
        {
            return new ConfigurationOptions(key, expirationInSeconds, issuer, audience);
        }
    }
}
