using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.VisualStudio.TestPlatform.TestHost;

namespace Jwt.Authenticator.Api.Test.Startup
{
    public class SetupFixture : WebApplicationFactory<Program>
    {
        public SetupFixture() { }
    }
}
