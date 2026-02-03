using SafeVault.Models;
using System.Security.Claims;

namespace SafeVault.Services
{
    public interface IJwtTokenGenerator
    {
        string GenerateToken(User user);
        ClaimsPrincipal? ValidateToken(string token);
    }
}
