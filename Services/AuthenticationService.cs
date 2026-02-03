using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Models.DTOs;
using BCrypt.Net;

namespace SafeVault.Services
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly SafeVaultContext _context;
        private readonly IJwtTokenGenerator _jwtGenerator;
        private readonly IInputValidationService _inputValidation;

        public AuthenticationService(
            SafeVaultContext context,
            IJwtTokenGenerator jwtGenerator,
            IInputValidationService inputValidation)
        {
            _context = context;
            _jwtGenerator = jwtGenerator;
            _inputValidation = inputValidation;
        }

        public async Task<(bool Success, string Message, User? User)> RegisterUser(
            string username,
            string email,
            string password,
            string role = "User")
        {
            // Validate username and email
            var validationResult = _inputValidation.ValidateUser(username, email);
            if (!validationResult.IsValid)
            {
                return (false, string.Join(", ", validationResult.Errors), null);
            }

            // Validate password
            var passwordValidation = ValidatePassword(password);
            if (!passwordValidation.IsValid)
            {
                return (false, string.Join(", ", passwordValidation.Errors), null);
            }

            // Check if username already exists
            var existingUser = await _context.Users
                .FirstOrDefaultAsync(u => u.Username == username);
            
            if (existingUser != null)
            {
                return (false, "Username already exists", null);
            }

            // Check if email already exists
            var existingEmail = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == email);
            
            if (existingEmail != null)
            {
                return (false, "Email already exists", null);
            }

            // Validate role
            if (role != "User" && role != "Admin")
            {
                return (false, "Invalid role. Must be 'User' or 'Admin'", null);
            }

            // Hash password and create user
            var passwordHash = HashPassword(password);
            
            var user = new User
            {
                Username = username,
                Email = email,
                PasswordHash = passwordHash,
                Role = role,
                CreatedAt = DateTime.UtcNow,
                IsActive = true
            };

            try
            {
                _context.Users.Add(user);
                await _context.SaveChangesAsync();
                return (true, "User registered successfully", user);
            }
            catch (Exception ex)
            {
                return (false, $"Registration failed: {ex.Message}", null);
            }
        }

        public async Task<LoginResponse> AuthenticateUser(string username, string password)
        {
            // Basic validation
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                return new LoginResponse
                {
                    Success = false,
                    Message = "Username and password are required"
                };
            }

            // Find user by username
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Username == username);

            if (user == null)
            {
                // Return generic error to prevent username enumeration
                return new LoginResponse
                {
                    Success = false,
                    Message = "Invalid username or password"
                };
            }

            // Check if account is active
            if (!user.IsActive)
            {
                return new LoginResponse
                {
                    Success = false,
                    Message = "Account is inactive. Please contact administrator."
                };
            }

            // Verify password
            if (!VerifyPassword(password, user.PasswordHash))
            {
                return new LoginResponse
                {
                    Success = false,
                    Message = "Invalid username or password"
                };
            }

            // Update last login time
            user.LastLoginAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            // Generate JWT token
            var token = _jwtGenerator.GenerateToken(user);

            return new LoginResponse
            {
                Success = true,
                Message = "Login successful",
                Token = token,
                User = new UserResponse
                {
                    UserID = user.UserID,
                    Username = user.Username,
                    Email = user.Email,
                    Role = user.Role,
                    CreatedAt = user.CreatedAt,
                    LastLoginAt = user.LastLoginAt,
                    IsActive = user.IsActive
                }
            };
        }

        public string HashPassword(string password)
        {
            // BCrypt automatically generates a salt and includes it in the hash
            // Cost factor 12 provides good security while maintaining performance
            return BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);
        }

        public bool VerifyPassword(string password, string passwordHash)
        {
            try
            {
                // BCrypt.Verify uses constant-time comparison to prevent timing attacks
                return BCrypt.Net.BCrypt.Verify(password, passwordHash);
            }
            catch
            {
                return false;
            }
        }

        public ValidationResult ValidatePassword(string password)
        {
            var result = new ValidationResult { IsValid = true };

            if (string.IsNullOrWhiteSpace(password))
            {
                result.IsValid = false;
                result.Errors.Add("Password is required");
                return result;
            }

            if (password.Length < 8)
            {
                result.IsValid = false;
                result.Errors.Add("Password must be at least 8 characters long");
            }

            if (password.Length > 128)
            {
                result.IsValid = false;
                result.Errors.Add("Password cannot exceed 128 characters");
            }

            if (!password.Any(char.IsUpper))
            {
                result.IsValid = false;
                result.Errors.Add("Password must contain at least one uppercase letter");
            }

            if (!password.Any(char.IsLower))
            {
                result.IsValid = false;
                result.Errors.Add("Password must contain at least one lowercase letter");
            }

            if (!password.Any(char.IsDigit))
            {
                result.IsValid = false;
                result.Errors.Add("Password must contain at least one digit");
            }

            if (!password.Any(c => !char.IsLetterOrDigit(c)))
            {
                result.IsValid = false;
                result.Errors.Add("Password must contain at least one special character");
            }

            // Check for common passwords (basic list)
            var commonPasswords = new[] { "Password1!", "Welcome1!", "Admin123!", "Qwerty123!" };
            if (commonPasswords.Contains(password))
            {
                result.IsValid = false;
                result.Errors.Add("Password is too common. Please choose a stronger password");
            }

            return result;
        }
    }
}
