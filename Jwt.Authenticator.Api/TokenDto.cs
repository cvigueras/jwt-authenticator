namespace Jwt.Authenticator.Api.Test
{
    public record TokenDto(string access_token, string refresh_token, string expires_in);
    
}