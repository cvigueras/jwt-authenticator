using Jwt.Authenticator.Auth.Models;

namespace Jwt.Authenticator.Auth.Services
{
    public interface IAuthenticatorService
    {
        string GetToken(LoginDto loginDto);
        string Auth(string token);
    }
}