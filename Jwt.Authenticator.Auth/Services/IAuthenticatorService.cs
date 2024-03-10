using Jwt.Authenticator.Auth.Models;
using System.Security.Claims;

namespace Jwt.Authenticator.Auth.Services
{
    public interface IAuthenticatorService
    {
        string ValidateJwtToken(string token);
        Token GenerateAccessToken(IEnumerable<Claim> userClaims);
        string GenerateRefreshToken();
    }
}