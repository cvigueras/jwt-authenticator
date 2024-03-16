namespace Jwt.Authenticator.Api
{
    public record TokenDto(string access_token, string refresh_token, string expires_in);

}