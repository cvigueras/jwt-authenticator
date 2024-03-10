using Jwt.Authenticator.Auth.Models;

namespace Jwt.Authenticator.Auth.Services
{
    public interface IAuthenticatorService
    {
        Token GenerateAccessToken(Login loginDto);
        string ValidateJwtToken(string token);
    }
}