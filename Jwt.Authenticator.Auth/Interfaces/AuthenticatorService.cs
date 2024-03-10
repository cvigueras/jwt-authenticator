using Jwt.Authenticator.Auth.Models;
using Jwt.Authenticator.Auth.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq.Expressions;
using System.Security.Claims;
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

        public string Auth(string token)
        {
            if(string.IsNullOrWhiteSpace(token))
            {
                throw new NullTokenException("Token must not be null");
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(!string.IsNullOrWhiteSpace(_config["Jwt:Key"]) ? _config["Jwt:Key"] : "SecretKey_1111111111100000000011");
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;
            var userId = jwtToken.Claims.First(x => x.Type == "sub").Value;

            return userId;
        }

        public Token GetToken(Login loginDto)
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

                var token = new JwtSecurityToken(_config["Jwt:Issuer"],
                    _config["Jwt:Issuer"],
                    claims,
                    expires: DateTime.Now.AddMinutes(expirationInMinutes),
                    signingCredentials: credentials);

                return new Token
                {
                    access_token = new JwtSecurityTokenHandler().WriteToken(token),
                    expires_in = GetExpirationInSeconds(expirationInMinutes)
                };
                //return new JwtSecurityTokenHandler().WriteToken(token);
            }
            catch (ArgumentOutOfRangeException ex)
            {
                throw new ArgumentOutOfRangeException("SecretKey must have at least 32 characters");
            }
            catch(Exception ex)
            {
                return null;
            }
        }

        private static int GetExpirationInSeconds(int expirationInMinutes)
        {
            return expirationInMinutes * 60;
        }
    }
}
