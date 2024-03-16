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
        private JwtSecurityTokenHandler tokenHandler;
        private ConfigurationOptions _configuration;

        public AuthenticatorService(IConfiguration config)
        {
            _config = config;
            tokenHandler = new JwtSecurityTokenHandler();
            _configuration = ConfigurationOptions.Create((byte[]?)Encoding.ASCII.GetBytes(_config["Jwt:Key"]),
                                                         int.Parse(_config["Jwt:Expiration"]),
                                                         _config["Jwt:Issuer"],
                                                         _config["Jwt:Audience"]);
        }

        public string? ValidateJwtToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                throw new NullTokenException("Token must not be null");
            }

            TokenValidationParameters validationParameters = GetTokenValidationParameters();
            SecurityToken validatedToken;
            var principal = GetClaimsPrincipal(token, tokenHandler, validationParameters, out validatedToken);

            if (validatedToken == null)
            {
                return null;
            }
            var jwtToken = (JwtSecurityToken)validatedToken;
            return principal?.Claims?.Where(c => c.Type == ClaimTypes.Name).Select(c => c.Value).SingleOrDefault();
        }

        public Token GenerateAccessToken(IEnumerable<Claim> userClaims)
        {
            try
            {
                var securityKey = new SymmetricSecurityKey(_configuration.Key);
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
                var tokenOptions = GetTokenOptions((int)_configuration.ExpirationInSeconds, credentials, userClaims);

                return new Token
                {
                    access_token = new JwtSecurityTokenHandler().WriteToken(tokenOptions),
                    expires_in = (int)_configuration.ExpirationInSeconds,
                    refresh_token = GenerateRefreshToken(),
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
        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        private JwtSecurityToken GetTokenOptions(int expirationInSeconds, SigningCredentials credentials, IEnumerable<Claim> claims)
        {
            return new JwtSecurityToken(
                   issuer: _configuration.Issuer,
                   audience: _configuration.Audience,
                   claims: claims,
                   expires: DateTime.Now.AddMinutes(expirationInSeconds),
                   signingCredentials: credentials
               );
        }

        private static ClaimsPrincipal GetClaimsPrincipal(string token,
                                                          JwtSecurityTokenHandler tokenHandler,
                                                          TokenValidationParameters validationParameters,
                                                          out SecurityToken validatedToken)
        {
            return tokenHandler.ValidateToken(token, validationParameters, out validatedToken);
        }

        private TokenValidationParameters GetTokenValidationParameters()
        {
            return new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(_configuration.Key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero
            };
        }
    }
}