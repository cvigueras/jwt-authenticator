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
        private byte[]? _key;
        private int? _expirationInSeconds;
        private string _issuer;
        private string _audience;

        public AuthenticatorService(IConfiguration config)
        {
            _config = config;
            tokenHandler = new JwtSecurityTokenHandler();
            _key = (byte[]?)Encoding.ASCII.GetBytes(_config["Jwt:Key"]);
            _expirationInSeconds = int.Parse(_config["Jwt:Expiration"]);
            _issuer = _config["Jwt:Issuer"];
            _audience = _config["Jwt:Audience"];
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
                var securityKey = new SymmetricSecurityKey(_key);
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
                var tokenOptions = GetTokenOptions((int)_expirationInSeconds, credentials, userClaims);

                return new Token
                {
                    access_token = new JwtSecurityTokenHandler().WriteToken(tokenOptions),
                    expires_in = (int)_expirationInSeconds,
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

        private JwtSecurityToken GetTokenOptions(int expirationInMinutes, SigningCredentials credentials, IEnumerable<Claim> claims)
        {
            return new JwtSecurityToken(
                   issuer: _issuer,
                   audience: _audience,
                   claims: claims,
                   expires: DateTime.Now.AddMinutes(expirationInMinutes),
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
                IssuerSigningKey = new SymmetricSecurityKey(_key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero
            };
        }
    }
}