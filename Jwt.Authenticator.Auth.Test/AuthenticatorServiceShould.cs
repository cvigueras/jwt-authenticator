using FluentAssertions;
using Jwt.Authenticator.Auth.Interfaces;
using Jwt.Authenticator.Auth.Models;
using Microsoft.Extensions.Configuration;
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
            var inMemorySettings = new Dictionary<string, string> {
                {"Jwt:Issuer", "Test.com"},
                {"Jwt:Key", "SecretKey_1111111111100000000011"},
            };
            configuration = new ConfigurationBuilder()
                            .AddInMemoryCollection(inMemorySettings)
                            .Build();
            authenticatorService = new AuthenticatorService(configuration);
        }

        [Test]
        public void GetTokenUserSuccesfully()
        {
            var token = authenticatorService.GetToken(loginDto);

            token.Should().NotBeEmpty();
        }

        [Test]
        public void AuthSuccessfullyByToken()
        {
            var token = authenticatorService.GetToken(loginDto);

            var result = authenticatorService.Auth(token);

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
            var inMemorySettings = new Dictionary<string, string> {
                {"Jwt:Issuer", "Test.com"},
                {"Jwt:Key", "SecretKey_1111111111100000000011"},
            };
            configuration = new ConfigurationBuilder()
                            .AddInMemoryCollection(inMemorySettings)
                            .Build();

            Action result = () => authenticatorService.GetToken(loginDto);

            result.Should().Throw<ArgumentOutOfRangeException>().WithMessage("SecretKey must have at least 32 characters");
        }
    }
}