namespace Jwt.Authenticator.Api
{
    public class UserRepository
    {
        private List<User> users;

        public UserRepository()
        {
            users = new List<User>
            {
                User.Create("Carlos", "1234", "carlos@carlos.com"),
                User.Create("Juan", "1234", "juan@juan.com"),
                User.Create("Pepe", "1234", "pepe@pepe.com"),
            };
        }

        public User? GetByUserNameAndPassword(string userName, string password)
        {
            return users.Where(x => x.UserName == userName && x.Password == password).FirstOrDefault();
        }        
        
        public User? GetByUserName(string userName)
        {
            return users.Where(x => x.UserName == userName).FirstOrDefault();
        }
    }
}
