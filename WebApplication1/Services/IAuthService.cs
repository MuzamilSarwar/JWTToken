using WebApplication1.Models;

namespace WebApplication1.Services
{
    public interface IAuthService
    {
        Task<User?> CreateUserAsync(UserDto user);
        Task<TokenResponseDto?> LoginAsync(LoginDto user);
        //string CreateToken(User user);
        Task<List<User>> GetAllUser(int? pagestart = 0, int? pageEnd = 10);

        Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto requestDto);
    }
}
