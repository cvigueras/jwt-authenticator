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
        private IConfiguration config;
        private LoginDto loginDto;

        [SetUp]
        public void SetUp()
        {
            loginDto = new LoginDto("user", "juan@juanito.com", DateTime.Now);
            config = Substitute.For<IConfiguration>();
            authenticatorService = new AuthenticatorService(config);
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
    }
}