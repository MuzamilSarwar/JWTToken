using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebApplication1.Models;

namespace WebApplication1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();

        [HttpPost("register")]
        public ActionResult<User> Register(User request)
        {
            var hassedPassword = new PasswordHasher<User>().HashPassword(user, request.PasswordHash);

            user.Name = request.Name;   
            user.PasswordHash = hassedPassword;

            return Ok(user);
        }
    }
}
