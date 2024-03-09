namespace Jwt.Authenticator.Auth
{
    public class AuthenticatorService : IAuthenticatorService
    {
        public string Auth(string token)
        {
            throw new NotImplementedException();
        }

        public string GetToken(LoginDto loginDto)
        {
            return "token";
        }
    }
}
