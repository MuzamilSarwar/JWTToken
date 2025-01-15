using Azure.Core;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using WebApplication1.Data;
using WebApplication1.Models;

namespace WebApplication1.Services
{
    public class AuthService : IAuthService
    {
        private readonly ProjectDbContext dbContext;
        private readonly IConfiguration configuration;

        public AuthService(ProjectDbContext dbContext, IConfiguration configuration)
        {
            this.dbContext = dbContext;
            this.configuration = configuration;
        }

        public async Task<List<User>> GetAllUser(int? pagestart = 0, int? pageEnd = 10)
        {
            return await dbContext.Users.Skip((int)pagestart).Take((int)pageEnd).ToListAsync();
        }
        public async Task<User?> CreateUserAsync(UserDto request)
        {
            //if (await dbContext.Users.AnyAsync(x => x.Name == request.Name))
            try
            {
                //var test =  dbContext.Users.Where(x => x.Name == request.Name).FirstOrDefault();
                //if (test is not null)
                if (await dbContext.Users.AnyAsync(x => x.Name == request.Name))
                    return null;
                else
                {
                    var user = new User();
                    var hassedPassword = new PasswordHasher<User>().HashPassword(user, request.Password);

                    user.Name = request.Name;
                    user.PasswordHash = hassedPassword;
                    await dbContext.Users.AddAsync(user);
                    dbContext.SaveChanges();
                    return user;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                throw;
            }
           
        }
        public async Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto requestDto)
        {
            var user = await ValidateRefreshTokenAsync(requestDto);
            if( user is null)
            {
                return null;
            }
            return await CreateToken(user);

        }

        private async Task<User?> ValidateRefreshTokenAsync(RefreshTokenRequestDto request)
        {
            var user = await dbContext.Users.FindAsync(request.Id);
            if( user is null || request.RefreshToken != user.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                return null;
            }
            return user;
        }
        public async Task<TokenResponseDto?> LoginAsync(LoginDto request)
        {
            var user = await dbContext.Users.FirstOrDefaultAsync(x => x.Name == request.Name);
            if (user is null)
            {
                return null;
            }
            else if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
            {
                return null;
            }
            return await CreateToken(user);
        }


        private async Task<TokenResponseDto> CreateToken(User user)
        {
            return new TokenResponseDto
            {
                AccessToken = CreatejwtToken(user),
                RefreshToken = await GenrateandSaveRefreshToken(user)
            };
        }

        private string GenrateRefreshtToken()
        {
            var rendomeNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(rendomeNumber);
            return Convert.ToBase64String(rendomeNumber);
        }

        private async Task<string> GenrateandSaveRefreshToken(User user)
        {
            var refreshToken = GenrateRefreshtToken();
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);
            await dbContext.SaveChangesAsync();
            return refreshToken;

        }
        private string CreatejwtToken(User user)
        {
            // claims
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Name),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Role, user.Role),
            };

            //signature key
            var key = new SymmetricSecurityKey(
                                        Encoding.UTF8.GetBytes(configuration.GetValue<string>("Appsettings:Token")!));

            var credientials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

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
