using Jwt.Authenticator.Auth.Models;

namespace Jwt.Authenticator.Auth.Services
{
    public interface IAuthenticatorService
    {
        string GetToken(Login loginDto);
        string Auth(string token);
    }
}