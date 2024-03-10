using FluentAssertions;
using Jwt.Authenticator.Auth.Interfaces;
using Jwt.Authenticator.Auth.Models;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json.Linq;
using NSubstitute;
using NUnit.Framework;

namespace Jwt.Authenticator.Auth.Test
{
    public class AuthenticatorServiceShould
    {
        private const int Expiration = 60;
        private AuthenticatorService authenticatorService;
        private IConfiguration configuration;
        private Login loginDto;

        [SetUp]
        public void SetUp()
        {
            loginDto = new Login("user", "juan@juanito.com", DateTime.Now);
        }

        [Test]
        public void GetTokenUserSuccesfully()
        {
            MockConfigurationBuilder("SecretKey_1111111111100000000011", "Test.com", Expiration);

            var token = authenticatorService.GenerateAccessToken(loginDto);

            token.Should().NotBeNull();
        }

        [Test]
        public void AuthSuccessfullyByToken()
        {
            MockConfigurationBuilder("SecretKey_1111111111100000000011", "Test.com", Expiration);

            var token = authenticatorService.GenerateAccessToken(loginDto);

            var result = authenticatorService.ValidateJwtToken(token.access_token);

            result.Should().Be(loginDto.userName);
        }

        [Test]
        public void GetNullTokenExceptionWhenTokenIsNullOrEmpty()
        {
            string token = null;

            Action result = () => authenticatorService.ValidateJwtToken(token);

            result.Should().Throw<NullTokenException>().WithMessage("Token must not be null");
        }

        [Test]
        public void GetArgumentOutOfRangeExceptionWhenSecretKeyIsTooShort()
        {
            MockConfigurationBuilder("SecretKey", "Test.com", Expiration);

            Action result = () => authenticatorService.GenerateAccessToken(loginDto);

            result.Should().Throw<ArgumentOutOfRangeException>().WithMessage("Specified argument was out of the range of valid values. " +
                "(Parameter 'SecretKey must have at least 32 characters')");
        }

        [Test]
        public void ExpiresTokenInOneHour()
        {
            MockConfigurationBuilder("SecretKey_1111111111100000000011", "Test.com", Expiration);

            var token = authenticatorService.GenerateAccessToken(loginDto);

            token.expires_in.Should().Be(Expiration * 60);
        }

        private void MockConfigurationBuilder(string key, string issuer, int expiration)
        {
            var inMemorySettings = new Dictionary<string, string> {
                {"Jwt:Issuer", issuer },
                {"Jwt:Key", key },
                {"Jwt:Expiration", expiration.ToString() },
                {"Jwt:Audicence", "https://localhost:5001" },
            };
            configuration = new ConfigurationBuilder()
                            .AddInMemoryCollection(inMemorySettings)
                            .Build();
            authenticatorService = new AuthenticatorService(configuration);
        }
    }
}