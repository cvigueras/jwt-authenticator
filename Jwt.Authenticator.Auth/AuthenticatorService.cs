namespace Jwt.Authenticator.Auth
{
    public class AuthenticatorService : IAuthenticatorService
    {
        public string Auth(string token)
        {
            return "user";
        }

        public string GetToken(LoginDto loginDto)
        {
            return "token";
        }
    }
}
