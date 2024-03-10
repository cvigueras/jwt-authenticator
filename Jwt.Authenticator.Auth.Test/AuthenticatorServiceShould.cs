﻿using FluentAssertions;
using Jwt.Authenticator.Auth.Interfaces;
using Jwt.Authenticator.Auth.Models;
using Microsoft.Extensions.Configuration;
using NUnit.Framework;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Jwt.Authenticator.Auth.Test
{
    public class AuthenticatorServiceShould
    {
        private const int Expiration = 60;
        private JwtSecurityTokenHandler tokenHandler;
        private AuthenticatorService authenticatorService;
        private IConfiguration configuration;
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
            MockConfigurationBuilder("SecretKey_1111111111100000000011", "Test.com", Expiration);

            var token = authenticatorService.GenerateAccessToken(claims);

            token.Should().NotBeNull();
        }

        [Test]
        public void AuthSuccessfullyByToken()
        {
            MockConfigurationBuilder("SecretKey_1111111111100000000011", "Test.com", Expiration);

            var token = authenticatorService.GenerateAccessToken(claims);

            var result = authenticatorService.ValidateJwtToken(token.access_token);

            result.Should().Be(user);
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

            Action result = () => authenticatorService.GenerateAccessToken(claims);

            result.Should().Throw<ArgumentOutOfRangeException>().WithMessage("Specified argument was out of the range of valid values. " +
                "(Parameter 'SecretKey must have at least 32 characters')");
        }

        [Test]
        public void ExpiresTokenInOneHour()
        {
            MockConfigurationBuilder("SecretKey_1111111111100000000011", "Test.com", Expiration);

            var token = authenticatorService.GenerateAccessToken(claims);

            token.expires_in.Should().Be(Expiration * 60);
        }

        [Test]
        public void GetRefreshTokenUserSuccesfully()
        {
            MockConfigurationBuilder("SecretKey_1111111111100000000011", "Test.com", Expiration);

            var token = authenticatorService.GenerateAccessToken(claims);

            token.refresh_token.Should().NotBeNull();
        }

        [Test]
        public void RefreshTokenSuccessfully()
        {
            MockConfigurationBuilder("SecretKey_1111111111100000000011", "Test.com", Expiration);

            var token = authenticatorService.GenerateAccessToken(claims);
            token = authenticatorService.RefreshToken(claims, token.access_token);
            var result = authenticatorService.ValidateJwtToken(token.access_token);

            result.Should().Be(user);
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