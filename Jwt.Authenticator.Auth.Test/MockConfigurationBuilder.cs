using Jwt.Authenticator.Auth.Models;
using Microsoft.Extensions.Configuration;

namespace Jwt.Authenticator.Auth.Test
{
    public static class MockConfigurationBuilder
    {
        public static IConfiguration SetConfg(string secret, string issuer, int expiration)
        {
            var inMemorySettings = new Dictionary<string, string> {
                {"JWT:Issuer", issuer },
                {"JWT:Secret", secret },
                {"JWT:Expiration", expiration.ToString() },
                {"JWT:Audience", "https://localhost:5001" },
            };
            return new ConfigurationBuilder()
            .AddInMemoryCollection(inMemorySettings)
                            .Build();
        }
    }
}
