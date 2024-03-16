using Microsoft.AspNetCore.Mvc;

namespace Jwt.Authenticator.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : Controller
    {
        [HttpPost]
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(TokenDto))]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult> Post([FromBody] UserDto user)
        {
            return Ok(new TokenDto("kaskjjhd", "kajsdlk", "3600"));
        }
    }
}
