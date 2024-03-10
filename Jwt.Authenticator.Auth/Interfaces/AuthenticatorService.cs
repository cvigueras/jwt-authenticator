using Jwt.Authenticator.Auth.Models;
using Jwt.Authenticator.Auth.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Jwt.Authenticator.Auth.Interfaces
{
    public class AuthenticatorService : IAuthenticatorService
    {
        private IConfiguration _config;
        public AuthenticatorService(IConfiguration config)
        {
            _config = config;
        }

        public string ValidateJwtToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                throw new NullTokenException("Token must not be null");
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            TokenValidationParameters validationParameters = GetTokenValidationParameters((byte[]?)Encoding.ASCII.GetBytes(_config["Jwt:Key"]));
            SecurityToken validatedToken;
            ValidateToken(token, tokenHandler, validationParameters, out validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;
            var userId = jwtToken.Claims.First(x => x.Type == "sub").Value;

            return userId;
        }

        private static ClaimsPrincipal ValidateToken(string token, JwtSecurityTokenHandler tokenHandler, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            return tokenHandler.ValidateToken(token, validationParameters, out validatedToken);
        }

        private static TokenValidationParameters GetTokenValidationParameters(byte[] key)
        {
            return new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero
            };
        }

        public Token GenerateAccessToken(Login loginDto)
        {
            try
            {
                int expirationInMinutes = int.Parse(_config["Jwt:Expiration"]);
                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

                var claims = new[] {
                new Claim(JwtRegisteredClaimNames.Sub, loginDto.userName),
                new Claim(JwtRegisteredClaimNames.Email, loginDto.emailAddress),
                new Claim("DateOfJoing", loginDto.dateOfJoing.ToString("yyyy-MM-dd")),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

                var tokenOptions = new JwtSecurityToken(
                       issuer: _config["Jwt:Issuer"],
                       audience: _config["Jwt:Audience"],
                       claims: claims,
                       expires: DateTime.Now.AddMinutes(expirationInMinutes),
                       signingCredentials: credentials
                   );

                return new Token
                {
                    access_token = new JwtSecurityTokenHandler().WriteToken(tokenOptions),
                    expires_in = GetExpirationInSeconds(expirationInMinutes)
                };
            }
            catch (ArgumentOutOfRangeException ex)
            {
                throw new ArgumentOutOfRangeException("SecretKey must have at least 32 characters");
            }
            catch (Exception ex)
            {
                return null;
            }
        }
        public string GenerateRefreshToken(Login loginDto)
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        private static int GetExpirationInSeconds(int expirationInMinutes)
        {
            return expirationInMinutes * 60;
        }

    }
}
