using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApplication1.Models;
using WebApplication1.Services;

namespace WebApplication1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public AuthController(IAuthService authService)
        {
            this.authService = authService;
        }
        //public static User user = new User();
        private readonly IAuthService authService;

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            var result = await authService.CreateUserAsync(request);
            if (result is null) {
                return BadRequest("User Already Exist");
            }
            //var hassedPassword = new PasswordHasher<User>().HashPassword(user, request.PasswordHash);

            //user.Name = request.Name;
            //user.PasswordHash = hassedPassword;

            return Ok(result);
        }

        [HttpPost("login")]

        public ActionResult<string> Login(UserDto request)
        {
            //if (user.Name != request.Name)
            //    return BadRequest("User Name Doesn't Exist");

            //if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.PasswordHash) == PasswordVerificationResult.Failed)
            //    return BadRequest("Wrong Password");

            //string token = "Success";

            var result = authService.LoginAsync(request);

            return Ok(result);
        }

       
    }
}
