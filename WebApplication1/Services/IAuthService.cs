using WebApplication1.Models;

namespace WebApplication1.Services
{
    public interface IAuthService
    {
        Task<User?> CreateUserAsync(UserDto user);
        Task<string> LoginAsync(UserDto user);
        string CreateToken(User user);
    }
}
