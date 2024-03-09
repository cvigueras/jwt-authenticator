namespace Jwt.Authenticator.Auth
{
    public interface IAuthenticatorService
    {
        string GetToken(LoginDto loginDto);
        string Auth(string token);
    }
}