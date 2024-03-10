using Jwt.Authenticator.Auth.Models;

namespace Jwt.Authenticator.Auth.Services
{
    public interface IAuthenticatorService
    {
        Token GetToken(Login loginDto);
        string Auth(string token);
    }
}