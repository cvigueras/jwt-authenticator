namespace Jwt.Authenticator.Api
{
    public static class UserRepository
    {
        public static List<User> users = new List<User>
            {
                User.Create("Carlos", "1234", "carlos@carlos.com"),
                User.Create("Juan", "1234", "juan@juan.com"),
                User.Create("Pepe", "1234", "pepe@pepe.com"),
            };

        public static User? GetByUserNameAndPassword(string userName, string password)
        {
            return users.Where(x => x.UserName == userName && x.Password == password).FirstOrDefault();
        }        
        
        public static User? GetByUserName(string userName)
        {
            return users.Where(x => x.UserName == userName).FirstOrDefault();
        }

        public static void SetTokenToUser(User user)
        {
            var userFound = GetByUserNameAndPassword(user.UserName, user.Password);
            userFound.RefreshToken = user.RefreshToken;
        }
    }
}
