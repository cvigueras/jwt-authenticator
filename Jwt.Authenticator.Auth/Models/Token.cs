namespace Jwt.Authenticator.Auth.Models
{
    public class Token
    {
        public object refresh_token;

        public string access_token { get; set; }
        public int expires_in { get; set; }
    }
}