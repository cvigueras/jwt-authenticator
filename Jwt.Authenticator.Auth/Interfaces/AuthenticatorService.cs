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
        public AuthenticatorService(IConfiguration config)
        {
            _config = config;
            tokenHandler = new JwtSecurityTokenHandler();
        }

        public string ValidateJwtToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                throw new NullTokenException("Token must not be null");
            }

            TokenValidationParameters validationParameters = GetTokenValidationParameters((byte[]?)Encoding.ASCII.GetBytes(_config["Jwt:Key"]));
            SecurityToken validatedToken;
            var principal = GetClaimsPrincipal(token, tokenHandler, validationParameters, out validatedToken);

            if (validatedToken != null)
            {
                var jwtToken = (JwtSecurityToken)validatedToken;
                return principal.Claims.Where(c => c.Type == ClaimTypes.Name).Select(c => c.Value).SingleOrDefault();

            }
            return null;
        }

        public Token GenerateAccessToken(IEnumerable<Claim> userClaims)
        {
            try
            {
                int expirationInMinutes = int.Parse(_config["Jwt:Expiration"]);
                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
                var tokenOptions = GetTokenOptions(expirationInMinutes, credentials, userClaims);

                return new Token
                {
                    access_token = new JwtSecurityTokenHandler().WriteToken(tokenOptions),
                    expires_in = GetExpirationInSeconds(expirationInMinutes),
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

        public Token RefreshToken(IEnumerable<Claim> claims, string access_token)
        {
            SecurityToken validatedToken;
            var principal = GetClaimsPrincipal(access_token, tokenHandler, GetTokenValidationParameters((byte[]?)Encoding.ASCII.GetBytes(_config["Jwt:Key"])), out validatedToken);
            var token = GenerateAccessToken(claims);
            var refresh_token = GenerateRefreshToken();
            return new Token
            {
                access_token = token.access_token,
                refresh_token = refresh_token,
                expires_in = token.expires_in
            };
        }

        private JwtSecurityToken GetTokenOptions(int expirationInMinutes, SigningCredentials credentials, IEnumerable<Claim> claims)
        {
            return new JwtSecurityToken(
                   issuer: _config["Jwt:Issuer"],
                   audience: _config["Jwt:Audience"],
                   claims: claims,
                   expires: DateTime.Now.AddMinutes(expirationInMinutes),
                   signingCredentials: credentials
               );
        }

        private static ClaimsPrincipal GetClaimsPrincipal(string token, JwtSecurityTokenHandler tokenHandler, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
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
        private string GenerateRefreshToken()
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
