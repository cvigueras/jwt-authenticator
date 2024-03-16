using Microsoft.Extensions.Configuration;

namespace Jwt.Authenticator.Auth.Test
{
    public static class MockConfigurationBuilder
    {
        public static IConfiguration SetConfg(string key, string issuer, int expiration)
        {
            var inMemorySettings = new Dictionary<string, string> {
                {"Jwt:Issuer", issuer },
                {"Jwt:Key", key },
                {"Jwt:Expiration", expiration.ToString() },
                {"Jwt:Audicence", "https://localhost:5001" },
            };
            return new ConfigurationBuilder()
            .AddInMemoryCollection(inMemorySettings)
                            .Build();
        }
    }
}
