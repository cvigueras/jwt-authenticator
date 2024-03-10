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
            MockConfigurationBuilder("SecretKey_1111111111100000000011", "Test.com");

            var token = authenticatorService.GetToken(loginDto);

            token.Should().NotBeNull();
        }

        [Test]
        public void AuthSuccessfullyByToken()
        {
            MockConfigurationBuilder("SecretKey_1111111111100000000011", "Test.com");

            var token = authenticatorService.GetToken(loginDto);

            var result = authenticatorService.Auth(token.access_token);

            result.Should().Be(loginDto.userName);
        }

        [Test]
        public void GetNullTokenExceptionWhenTokenIsNullOrEmpty()
        {
            string token = null;

            Action result = () => authenticatorService.Auth(token);

            result.Should().Throw<NullTokenException>().WithMessage("Token must not be null");
        }

        [Test]
        public void GetArgumentOutOfRangeExceptionWhenSecretKeyIsTooShort()
        {
            MockConfigurationBuilder("SecretKey", "Test.com");

            Action result = () => authenticatorService.GetToken(loginDto);

            result.Should().Throw<ArgumentOutOfRangeException>().WithMessage("Specified argument was out of the range of valid values. (Parameter 'SecretKey must have at least 32 characters')");
        }

        [Test]
        public void ExpiresTokenInTwoHours()
        {
            MockConfigurationBuilder("SecretKey_1111111111100000000011", "Test.com");

            var token = authenticatorService.GetToken(loginDto);

            var now = new DateTimeOffset(DateTime.UtcNow.AddMinutes(120));
            token.expires_in.Should().BeInRange((int)now.ToUnixTimeSeconds(), (int)now.ToUnixTimeSeconds() + 5);
        }

        private void MockConfigurationBuilder(string key, string issuer)
        {
            var inMemorySettings = new Dictionary<string, string> {
                {"Jwt:Issuer", issuer },
                {"Jwt:Key", key },
            };
            configuration = new ConfigurationBuilder()
                            .AddInMemoryCollection(inMemorySettings)
                            .Build();
            authenticatorService = new AuthenticatorService(configuration);
        }
    }
}