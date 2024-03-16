using Jwt.Authenticator.Api.Test.Fixtures;
using Jwt.Authenticator.Api.Test.Startup;
using Newtonsoft.Json;

namespace Jwt.Authenticator.Api.Test
{
    public class JwtauthFeature
    {
        public const string RequestUriBase = "Auth";
        public const string PathJson = "./Fixtures/user.json";
        private JwtAuthenticatorClient client;

        [SetUp]
        public void Setup()
        {
            client = new JwtAuthenticatorClient(new SetupFixture().CreateClient());
        }

        [Test]
        public async Task GetTokenSuccessfullyAsync()
        {
            var json = await client.GetJsonContent(PathJson);

            var responsePost = await client.Post(RequestUriBase, json);

            var token = responsePost.Content.ReadAsStringAsync().Result;

            var tokenResult = JsonConvert.DeserializeObject<TokenDto>(token);

            var settings = new VerifySettings();

            await Verify(tokenResult, settings);
        }
    }
}