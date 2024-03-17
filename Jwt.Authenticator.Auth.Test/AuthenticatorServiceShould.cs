using FluentAssertions;
using Jwt.Authenticator.Auth.Exceptions;
using Jwt.Authenticator.Auth.Services;
using NUnit.Framework;
using System.Security.Claims;

namespace Jwt.Authenticator.Auth.Test
{
    public class AuthenticatorServiceShould
    {
        private const int ExpirationInSeconds = 3600;
        private AuthenticatorService authenticatorService;
        private IEnumerable<Claim> claims;
        string user = "user";
        string email = "juan@juanito.com";

        [SetUp]
        public void SetUp()
        {
            claims = new[]
            {
                new Claim(ClaimTypes.Name, user),
                new Claim(ClaimTypes.Email, email),
            };
        }

        [Test]
        public void GetTokenUserSuccesfully()
        {
            var configuration = MockConfigurationBuilder.SetConfg("SecretKey_1111111111100000000011", "Test.com", ExpirationInSeconds);
            authenticatorService = new AuthenticatorService(configuration);

            var token = authenticatorService.GenerateAccessToken(claims);

            token.Should().NotBeNull();
        }

        [Test]
        public void AuthSuccessfullyByToken()
        {
            var configuration = MockConfigurationBuilder.SetConfg("SecretKey_1111111111100000000011", "Test.com", ExpirationInSeconds);
            authenticatorService = new AuthenticatorService(configuration);
            var token = authenticatorService.GenerateAccessToken(claims);

            var result = authenticatorService.ValidateJwtToken(token.access_token);

            result.Identity.Name.Should().Be(user);
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
            var configuration = MockConfigurationBuilder.SetConfg("SecretKey", "Test.com", ExpirationInSeconds);
            authenticatorService = new AuthenticatorService(configuration);

            Action result = () => authenticatorService.GenerateAccessToken(claims);

            result.Should().Throw<ArgumentOutOfRangeException>().WithMessage("Specified argument was out of the range of valid values. " +
                "(Parameter 'SecretKey must have at least 32 characters')");
        }

        [Test]
        public void ExpiresTokenInOneHour()
        {
            var configuration = MockConfigurationBuilder.SetConfg("SecretKey_1111111111100000000011", "Test.com", ExpirationInSeconds);
            authenticatorService = new AuthenticatorService(configuration);

            var token = authenticatorService.GenerateAccessToken(claims);

            token.expires_in.Should().Be(ExpirationInSeconds);
        }

        [Test]
        public void GetRefreshTokenUserSuccesfully()
        {
            var configuration = MockConfigurationBuilder.SetConfg("SecretKey_1111111111100000000011", "Test.com", ExpirationInSeconds);
            authenticatorService = new AuthenticatorService(configuration);

            var refresh_token = authenticatorService.GenerateRefreshToken();

            refresh_token.Should().NotBeNull();
        }
    }
}