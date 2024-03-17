using FluentAssertions;
using Jwt.Authenticator.Api.Test.Fixtures;
using Jwt.Authenticator.Api.Test.Startup;
using Newtonsoft.Json;
using System.Net;

namespace Jwt.Authenticator.Api.Test
{
    public class JwtauthFeature
    {
        public const string RequestUriBase = "Auth";
        public const string UserJsonSuccess = "./Fixtures/user.json";
        public const string UserJsonUnauthorized = "./Fixtures/userko.json";
        private JwtAuthenticatorClient client;

        [SetUp]
        public void Setup()
        {
            client = new JwtAuthenticatorClient(new SetupFixture().CreateClient());
        }

        [Test]
        public async Task GetTokenSuccessfullyAsync()
        {
            var json = await client.GetJsonContent(UserJsonSuccess);

            var responsePost = await client.Post(RequestUriBase, json);
            var token = responsePost.Content.ReadAsStringAsync().Result;
            var tokenResult = JsonConvert.DeserializeObject<TokenDto>(token);

            responsePost.EnsureSuccessStatusCode();
            tokenResult.access_token.Should().NotBeNull();
            tokenResult.refresh_token.Should().NotBeNull();
            tokenResult.expires_in.Should().NotBeNull();
        }

        [Test]
        public async Task GetUnauthorizedResponseWhenUserNotExistAsync()
        {
            var json = await client.GetJsonContent(UserJsonUnauthorized);

            var responsePost = await client.Post(RequestUriBase, json);

            responsePost.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }
    }
}