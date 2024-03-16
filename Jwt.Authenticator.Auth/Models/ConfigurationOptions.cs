namespace Jwt.Authenticator.Auth.Models
{
    public class ConfigurationOptions
    {
        public byte[]? Key { get; }
        public int? ExpirationInSeconds { get; }
        public string? Issuer { get; }
        public string? Audience { get; }


        private ConfigurationOptions(byte[]? key, int? expirationInSeconds, string issuer, string audience)
        {
            Key = key;
            ExpirationInSeconds = expirationInSeconds;
            Issuer = issuer;
            Audience = audience;
        }

        public static ConfigurationOptions Create(byte[]? key, int? expirationInSeconds, string issuer, string audience)
        {
            return new ConfigurationOptions(key, expirationInSeconds, issuer, audience);
        }
    }
}
