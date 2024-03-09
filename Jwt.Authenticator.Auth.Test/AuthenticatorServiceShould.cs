using FluentAssertions;
using Jwt.Authenticator.Auth.Interfaces;
using Jwt.Authenticator.Auth.Models;
using Microsoft.Extensions.Configuration;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using NUnit.Framework;

namespace Jwt.Authenticator.Auth.Test
{
    public class AuthenticatorServiceShould
    {
        private AuthenticatorService authenticatorService;
        private IConfiguration config;
        private Login loginDto;

        [SetUp]
        public void SetUp()
        {
            loginDto = new Login("user", "juan@juanito.com", DateTime.Now);
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

        [Test]
        public void GetNullTokenExceptionWhenTokenIsNullOrEmpty()
        {
            string token = null;

            Action result = () => authenticatorService.Auth(token);

            result.Should().Throw<NullTokenException>().WithMessage("Token must not be null");
        }
    }
}