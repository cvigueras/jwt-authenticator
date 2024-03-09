using FluentAssertions;
using Microsoft.Extensions.Configuration;
using NSubstitute;
using NUnit.Framework;

namespace Jwt.Authenticator.Auth.Test
{
    public class AuthenticatorServiceShould
    {
        private AuthenticatorService authenticatorService;
        private IConfiguration config;

        [SetUp]
        public void SetUp()
        {
            config = Substitute.For<IConfiguration>();
            authenticatorService = new AuthenticatorService(config);
        }

        [Test]
        public void GetTokenUserSuccesfully()
        {
            var loginDto = new LoginDto("user", "juan@juanito.com", DateTime.Now);

            var token = authenticatorService.GetToken(loginDto);

            token.Should().NotBeEmpty();
        }

        [Test]
        public void AuthSuccessfully()
        {
            var loginDto = new LoginDto("user", "juan@juanito.com", DateTime.Now);

            var token = authenticatorService.GetToken(loginDto);

            var result = authenticatorService.Auth(token);

            result.Should().Be(loginDto.userName);

        }
    }
}