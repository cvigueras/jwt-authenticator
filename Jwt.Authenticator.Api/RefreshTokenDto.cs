namespace Jwt.Authenticator.Api
{
    public record RefreshTokenDto(string access_token, string refresh_token);
}
