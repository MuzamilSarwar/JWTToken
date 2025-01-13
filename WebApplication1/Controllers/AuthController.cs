using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApplication1.Models;

namespace WebApplication1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public AuthController(IConfiguration configuration)
        {
            this.configuration = configuration;
        }
        public static User user = new User();
        private readonly IConfiguration configuration;

        [HttpPost("register")]
        public ActionResult<User> Register(User request)
        {
            var hassedPassword = new PasswordHasher<User>().HashPassword(user, request.PasswordHash);

            user.Name = request.Name;
            user.PasswordHash = hassedPassword;

            return Ok(user);
        }

        [HttpPost("login")]

        public ActionResult<string> Login(User request)
        {
            if (user.Name != request.Name)
                return BadRequest("User Name Doesn't Exist");

            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.PasswordHash) == PasswordVerificationResult.Failed)
                return BadRequest("Wrong Password");

            //string token = "Success";

            return Ok(CreateToken(user));
        }

        private string CreateToken(User user)
        {
            // claims
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Name)
            };

            //signature key
            var key = new SymmetricSecurityKey(
                                        Encoding.UTF8.GetBytes(configuration.GetValue<string>("Appsettings:Token")!));

            var credientials = new SigningCredentials(key,SecurityAlgorithms.HmacSha256);

            // creating token description
            var tokenDescriptor = new JwtSecurityToken(
                                                issuer: configuration.GetValue<string>("Appsettings:Issuer"),
                                                audience: configuration.GetValue<string>("Appsettings:Audience"),
                                                claims: claims,
                                                signingCredentials: credientials,
                                                expires: DateTime.UtcNow.AddHours(1)
                                                );
            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }
    }
}
