using FluentAssertions;
using NSubstitute;
using NUnit.Framework;

namespace Jwt.Authenticator.Auth.Test
{
    public class AuthenticatorServiceShould
    {
        private AuthenticatorService authenticatorService;

        [SetUp]
        public void SetUp()
        {
            authenticatorService = new AuthenticatorService();
        }

        [Test]
        public void GetTokenUserSuccesfully()
        {
            var loginDto = new LoginDto("user", "password");

            var token = authenticatorService.GetToken(loginDto);

            token.Should().NotBeEmpty();
        }
    }
}