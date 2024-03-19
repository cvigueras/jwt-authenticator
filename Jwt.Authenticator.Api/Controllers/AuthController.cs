using Jwt.Authenticator.Auth.Interfaces;
using Jwt.Authenticator.Auth.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using System.Net;
using System.Security.Claims;

namespace Jwt.Authenticator.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : Controller
    {
        public IConfiguration Configuration { get; }
        public IAuthenticatorService _authenticatorService { get; }

        public AuthController(IConfiguration configuration, IAuthenticatorService authenticatorService)
        {
            Configuration = configuration;
            _authenticatorService = authenticatorService;
        }


        [HttpPost]
        [Route("GetToken")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(Token))]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult<Token>> GetToken([FromBody] UserDto request)
        {
            var user = UserRepository.GetByUserNameAndPassword(request.userName, request.password);
            if(user == null)
            {
               return Unauthorized("User or password incorrect!");
            }
            var token = _authenticatorService.GenerateAccessToken(GetClaims(user));
            user.RefreshToken = token.refresh_token;
            UserRepository.SetTokenToUser(user);
            return Ok(token);
        }

        [HttpPost]
        [Route("RefreshToken")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(Token))]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult<Token>> RefreshToken([FromBody] RefreshTokenDto request)
        {

            var principal = _authenticatorService.ValidateJwtToken(request.access_token);
            var user = UserRepository.GetByUserName(principal.Identity.Name);
            if (user == null || request.refresh_token == null || user.RefreshToken != request.refresh_token)
            {
                return Unauthorized("Refresh token incorrect!");
            }
            return Ok(_authenticatorService.GenerateAccessToken(GetClaims(user)));
        }


        private Claim[] GetClaims(User user)
        {
            return new[]
{
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email),
            };
        }
    }
}
