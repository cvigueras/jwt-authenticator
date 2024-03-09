namespace Jwt.Authenticator.Auth
{
    public class AuthenticatorService : IAuthenticatorService
    {
        public string GetToken(LoginDto loginDto)
        {
            return "token";
        }
    }
}
