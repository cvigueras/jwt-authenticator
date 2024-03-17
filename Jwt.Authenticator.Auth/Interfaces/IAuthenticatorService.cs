using Jwt.Authenticator.Auth.Models;
using System.Security.Claims;

namespace Jwt.Authenticator.Auth.Interfaces
{
    public interface IAuthenticatorService
    {
        ClaimsPrincipal ValidateJwtToken(string token);
        Token GenerateAccessToken(IEnumerable<Claim> userClaims);
        string GenerateRefreshToken();
    }
}