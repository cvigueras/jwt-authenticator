namespace Jwt.Authenticator.Auth
{
    public class NullTokenException : Exception
    {
        public NullTokenException(string message) : base(message)
        {
            
        }
    }
}