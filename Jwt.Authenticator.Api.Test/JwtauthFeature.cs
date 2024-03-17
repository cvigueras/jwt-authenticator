using FluentAssertions;
using Jwt.Authenticator.Api.Test.Fixtures;
using Jwt.Authenticator.Api.Test.Startup;
using Newtonsoft.Json;
using System.Net;

namespace Jwt.Authenticator.Api.Test
{
    public class JwtauthFeature
    {
        public const string PathGetToken = "Auth/GetToken";
        public const string PathRefreshToken = "Auth/RefreshToken";
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

            var responsePost = await client.Post(PathGetToken, json);
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

            var responsePost = await client.Post(PathGetToken, json);

            responsePost.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Test]
        public async Task GetNewTokenUsingRefreshTokenSuccessfully()
        {
            var jsonToken = await client.GetJsonContent(UserJsonSuccess);
            var responsePost = await client.Post(PathGetToken, jsonToken);
            var token = responsePost.Content.ReadAsStringAsync().Result;
            var tokenResult = JsonConvert.DeserializeObject<TokenDto>(token);

            var refreshTokenDto = new RefreshTokenDto(tokenResult.access_token, tokenResult.refresh_token);
            var refreshJsonSuccess = JsonConvert.SerializeObject(refreshTokenDto);
            var responsePostRefresh = await client.Post(PathRefreshToken, refreshJsonSuccess);
            var tokenRefresh = responsePostRefresh.Content.ReadAsStringAsync().Result;
            var tokenResultRefresh = JsonConvert.DeserializeObject<TokenDto>(tokenRefresh);

            responsePostRefresh.EnsureSuccessStatusCode();
            tokenResultRefresh.access_token.Should().NotBeNull();
            tokenResultRefresh.refresh_token.Should().NotBeNull();
            tokenResultRefresh.expires_in.Should().NotBeNull();

        }
    }    
}