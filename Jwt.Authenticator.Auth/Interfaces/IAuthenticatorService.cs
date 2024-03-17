using Jwt.Authenticator.Auth.Models;
using System.Security.Claims;

namespace Jwt.Authenticator.Auth.Interfaces
{
    public interface IAuthenticatorService
    {
        string ValidateJwtToken(string token);
        Token GenerateAccessToken(IEnumerable<Claim> userClaims);
        string GenerateRefreshToken();
    }
}