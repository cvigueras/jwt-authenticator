using Jwt.Authenticator.Auth.Interfaces;
using Jwt.Authenticator.Auth.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
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

        private UserRepository _userRepository;

        public AuthController(IConfiguration configuration, IAuthenticatorService authenticatorService)
        {
            Configuration = configuration;
            _authenticatorService = authenticatorService;
            _userRepository = new UserRepository();
        }


        [HttpPost]
        [Route("GetToken")]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(Token))]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<ActionResult<Token>> GetToken([FromBody] UserDto request)
        {
            var user = _userRepository.GetByUserName(request.userName, request.password);
            if(user == null)
            {
               return Unauthorized("User or password incorrect!");
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
