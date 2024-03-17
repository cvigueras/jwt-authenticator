namespace Jwt.Authenticator.Api
{
    public class User
    {
        public string UserName { get; }
        public string Password { get; }
        public string Email { get; }

        private User(string userName, string password, string email)
        {
            UserName = userName;
            Password = password;
            Email = email;
        }

        public static User Create(string userName, string password, string email)
        {
            return new User(userName, password, email);
        }
    }
}
