using Jwt.Authenticator.Auth.Models;
using Microsoft.Extensions.Configuration;

namespace Jwt.Authenticator.Auth.Test
{
    public static class MockConfigurationBuilder
    {
        public static ConfigurationOptions SetConfg(string key, string issuer, int expiration, string audience)
        {
            return ConfigurationOptions.Create(key, expiration, issuer, audience);
        }
    }
}
