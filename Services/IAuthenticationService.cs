using SafeVault.Models;
using SafeVault.Models.DTOs;

namespace SafeVault.Services
{
    public interface IAuthenticationService
    {
        Task<(bool Success, string Message, User? User)> RegisterUser(string username, string email, string password, string role = "User");
        Task<LoginResponse> AuthenticateUser(string username, string password);
        string HashPassword(string password);
        bool VerifyPassword(string password, string passwordHash);
        ValidationResult ValidatePassword(string password);
    }
}
