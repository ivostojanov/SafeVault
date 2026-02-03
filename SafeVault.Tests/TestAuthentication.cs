using Xunit;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace SafeVault.Tests
{
    /// <summary>
    /// Comprehensive authentication tests.
    /// Tests user registration, password hashing, login functionality,
    /// JWT token generation, and authentication security.
    /// </summary>
    public class TestAuthentication
    {
        private SafeVaultContext _dbContext;
        private IAuthenticationService _authService;
        private IJwtTokenGenerator _jwtGenerator;
        private IInputValidationService _validationService;

        public TestAuthentication()
        {
            // Setup in-memory database
            var options = new DbContextOptionsBuilder<SafeVaultContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            _dbContext = new SafeVaultContext(options);
            _dbContext.Database.EnsureCreated();

            // Setup configuration for JWT
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["JwtSettings:SecretKey"] = "Test-Secret-Key-At-Least-32-Characters-Long-For-Security",
                    ["JwtSettings:Issuer"] = "SafeVaultTest",
                    ["JwtSettings:Audience"] = "SafeVaultTestUsers",
                    ["JwtSettings:ExpirationMinutes"] = "60"
                })
                .Build();

            _jwtGenerator = new JwtTokenGenerator(configuration);
            _validationService = new InputValidationService();
            _authService = new AuthenticationService(_dbContext, _jwtGenerator, _validationService);
        }

        #region User Registration Tests

        [Fact]
        public async Task Test_RegisterUser_WithValidCredentials_Succeeds()
        {
            // Arrange
            string username = "john_doe";
            string email = "john@example.com";
            string password = "SecurePass123!";

            // Act
            var (success, message, user) = await _authService.RegisterUser(username, email, password);

            // Assert
            Assert.True(success);
            Assert.Equal("User registered successfully", message);
            Assert.NotNull(user);
            Assert.Equal(username, user.Username);
            Assert.Equal("User", user.Role);
            Assert.True(user.IsActive);
        }

        [Fact]
        public async Task Test_RegisterUser_PasswordIsHashed()
        {
            // Arrange
            string username = "testuser";
            string email = "test@example.com";
            string password = "MyPassword123!";

            // Act
            var (success, message, user) = await _authService.RegisterUser(username, email, password);

            // Assert
            Assert.True(success);
            Assert.NotNull(user);
            Assert.NotEqual(password, user.PasswordHash); // Password should be hashed
            Assert.NotEmpty(user.PasswordHash);
            Assert.True(user.PasswordHash.Length > 50); // BCrypt hashes are 60 chars
        }

        [Fact]
        public async Task Test_RegisterUser_DuplicateUsername_Fails()
        {
            // Arrange
            string username = "duplicate_user";
            string email1 = "user1@example.com";
            string email2 = "user2@example.com";
            string password = "SecurePass123!";

            // Act - Register first user
            await _authService.RegisterUser(username, email1, password);

            // Act - Try to register second user with same username
            var (success, message, user) = await _authService.RegisterUser(username, email2, password);

            // Assert
            Assert.False(success);
            Assert.Contains("Username already exists", message);
            Assert.Null(user);
        }

        [Fact]
        public async Task Test_RegisterUser_DuplicateEmail_Fails()
        {
            // Arrange
            string username1 = "user1";
            string username2 = "user2";
            string email = "duplicate@example.com";
            string password = "SecurePass123!";

            // Act - Register first user
            await _authService.RegisterUser(username1, email, password);

            // Act - Try to register second user with same email
            var (success, message, user) = await _authService.RegisterUser(username2, email, password);

            // Assert
            Assert.False(success);
            Assert.Contains("Email already exists", message);
            Assert.Null(user);
        }

        [Fact]
        public async Task Test_RegisterUser_WithWeakPassword_Fails()
        {
            // Arrange
            string username = "testuser";
            string email = "test@example.com";
            string weakPassword = "weak"; // Too short, no uppercase, no special char

            // Act
            var (success, message, user) = await _authService.RegisterUser(username, email, weakPassword);

            // Assert
            Assert.False(success);
            Assert.Null(user);
            // Should contain password requirements errors
            Assert.Contains("8 characters", message);
        }

        [Fact]
        public async Task Test_RegisterUser_WithInvalidUsername_Fails()
        {
            // Arrange
            string invalidUsername = "user@invalid"; // Contains @ symbol
            string email = "test@example.com";
            string password = "SecurePass123!";

            // Act
            var (success, message, user) = await _authService.RegisterUser(invalidUsername, email, password);

            // Assert
            Assert.False(success);
            Assert.Null(user);
        }

        [Fact]
        public async Task Test_RegisterUser_WithInvalidEmail_Fails()
        {
            // Arrange
            string username = "testuser";
            string invalidEmail = "not-an-email";
            string password = "SecurePass123!";

            // Act
            var (success, message, user) = await _authService.RegisterUser(username, invalidEmail, password);

            // Assert
            Assert.False(success);
            Assert.Null(user);
        }

        #endregion

        #region Password Hashing Tests

        [Fact]
        public void Test_HashPassword_GeneratesDifferentHashesForSamePassword()
        {
            // Arrange
            string password = "TestPassword123!";

            // Act - Hash the same password twice
            string hash1 = _authService.HashPassword(password);
            string hash2 = _authService.HashPassword(password);

            // Assert - Hashes should be different (BCrypt generates unique salt each time)
            Assert.NotEqual(hash1, hash2);
        }

        [Fact]
        public void Test_VerifyPassword_WithCorrectPassword_ReturnsTrue()
        {
            // Arrange
            string password = "TestPassword123!";
            string hash = _authService.HashPassword(password);

            // Act
            bool isValid = _authService.VerifyPassword(password, hash);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void Test_VerifyPassword_WithIncorrectPassword_ReturnsFalse()
        {
            // Arrange
            string correctPassword = "TestPassword123!";
            string incorrectPassword = "WrongPassword123!";
            string hash = _authService.HashPassword(correctPassword);

            // Act
            bool isValid = _authService.VerifyPassword(incorrectPassword, hash);

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public void Test_VerifyPassword_WithInvalidHash_ReturnsFalse()
        {
            // Arrange
            string password = "TestPassword123!";
            string invalidHash = "not-a-valid-bcrypt-hash";

            // Act
            bool isValid = _authService.VerifyPassword(password, invalidHash);

            // Assert
            Assert.False(isValid);
        }

        #endregion

        #region Password Validation Tests

        [Fact]
        public void Test_ValidatePassword_ValidPassword_Passes()
        {
            // Arrange
            string validPassword = "SecurePass123!";

            // Act
            var result = _authService.ValidatePassword(validPassword);

            // Assert
            Assert.True(result.IsValid);
            Assert.Empty(result.Errors);
        }

        [Fact]
        public void Test_ValidatePassword_TooShort_Fails()
        {
            // Arrange
            string shortPassword = "Pass1!";

            // Act
            var result = _authService.ValidatePassword(shortPassword);

            // Assert
            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, e => e.Contains("8 characters"));
        }

        [Fact]
        public void Test_ValidatePassword_NoUppercase_Fails()
        {
            // Arrange
            string password = "lowercase123!";

            // Act
            var result = _authService.ValidatePassword(password);

            // Assert
            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, e => e.Contains("uppercase"));
        }

        [Fact]
        public void Test_ValidatePassword_NoLowercase_Fails()
        {
            // Arrange
            string password = "UPPERCASE123!";

            // Act
            var result = _authService.ValidatePassword(password);

            // Assert
            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, e => e.Contains("lowercase"));
        }

        [Fact]
        public void Test_ValidatePassword_NoDigit_Fails()
        {
            // Arrange
            string password = "NoDigitsHere!";

            // Act
            var result = _authService.ValidatePassword(password);

            // Assert
            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, e => e.Contains("digit"));
        }

        [Fact]
        public void Test_ValidatePassword_NoSpecialCharacter_Fails()
        {
            // Arrange
            string password = "NoSpecialChar123";

            // Act
            var result = _authService.ValidatePassword(password);

            // Assert
            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, e => e.Contains("special character"));
        }

        [Fact]
        public void Test_ValidatePassword_TooLong_Fails()
        {
            // Arrange
            string tooLongPassword = new string('a', 129) + "A1!";

            // Act
            var result = _authService.ValidatePassword(tooLongPassword);

            // Assert
            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, e => e.Contains("128 characters"));
        }

        [Fact]
        public void Test_ValidatePassword_CommonPassword_Fails()
        {
            // Arrange
            string commonPassword = "Password1!";

            // Act
            var result = _authService.ValidatePassword(commonPassword);

            // Assert
            Assert.False(result.IsValid);
            Assert.Contains(result.Errors, e => e.Contains("too common"));
        }

        #endregion

        #region Login Tests

        [Fact]
        public async Task Test_Login_WithValidCredentials_Succeeds()
        {
            // Arrange - Register a user first
            string username = "logintest";
            string email = "login@example.com";
            string password = "LoginPass123!";
            await _authService.RegisterUser(username, email, password);

            // Act - Attempt login
            var response = await _authService.AuthenticateUser(username, password);

            // Assert
            Assert.True(response.Success);
            Assert.NotEmpty(response.Token);
            Assert.NotNull(response.User);
            Assert.Equal(username, response.User.Username);
        }

        [Fact]
        public async Task Test_Login_WithIncorrectPassword_Fails()
        {
            // Arrange - Register a user
            string username = "testuser";
            string email = "test@example.com";
            string correctPassword = "CorrectPass123!";
            string incorrectPassword = "WrongPass123!";
            await _authService.RegisterUser(username, email, correctPassword);

            // Act - Try to login with wrong password
            var response = await _authService.AuthenticateUser(username, incorrectPassword);

            // Assert
            Assert.False(response.Success);
            Assert.Empty(response.Token);
            Assert.Equal("Invalid username or password", response.Message);
        }

        [Fact]
        public async Task Test_Login_WithNonExistentUsername_Fails()
        {
            // Arrange
            string nonExistentUsername = "nonexistent";
            string password = "SomePass123!";

            // Act
            var response = await _authService.AuthenticateUser(nonExistentUsername, password);

            // Assert
            Assert.False(response.Success);
            Assert.Empty(response.Token);
            Assert.Equal("Invalid username or password", response.Message);
        }

        [Fact]
        public async Task Test_Login_UpdatesLastLoginTime()
        {
            // Arrange - Register a user
            string username = "timestamptest";
            string email = "timestamp@example.com";
            string password = "TimePass123!";
            await _authService.RegisterUser(username, email, password);

            // Act - Login
            var beforeLogin = DateTime.UtcNow;
            await _authService.AuthenticateUser(username, password);
            var afterLogin = DateTime.UtcNow;

            // Assert - Check LastLoginAt was updated
            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == username);
            Assert.NotNull(user);
            Assert.NotNull(user.LastLoginAt);
            Assert.True(user.LastLoginAt >= beforeLogin && user.LastLoginAt <= afterLogin);
        }

        [Fact]
        public async Task Test_Login_WithEmptyUsername_Fails()
        {
            // Arrange
            string emptyUsername = "";
            string password = "SomePass123!";

            // Act
            var response = await _authService.AuthenticateUser(emptyUsername, password);

            // Assert
            Assert.False(response.Success);
            Assert.Equal("Username and password are required", response.Message);
        }

        [Fact]
        public async Task Test_Login_WithEmptyPassword_Fails()
        {
            // Arrange
            string username = "testuser";
            string emptyPassword = "";

            // Act
            var response = await _authService.AuthenticateUser(username, emptyPassword);

            // Assert
            Assert.False(response.Success);
            Assert.Equal("Username and password are required", response.Message);
        }

        #endregion

        #region JWT Token Tests

        [Fact]
        public void Test_GenerateToken_CreatesValidJWT()
        {
            // Arrange
            var user = new User
            {
                UserID = 1,
                Username = "testuser",
                Email = "test@example.com",
                PasswordHash = "hashedpassword",
                Role = "User",
                IsActive = true
            };

            // Act
            string token = _jwtGenerator.GenerateToken(user);

            // Assert
            Assert.NotEmpty(token);
            Assert.Contains(".", token); // JWT format: header.payload.signature
        }

        [Fact]
        public void Test_ValidateToken_WithValidToken_ReturnsClaimsPrincipal()
        {
            // Arrange
            var user = new User
            {
                UserID = 1,
                Username = "testuser",
                Email = "test@example.com",
                PasswordHash = "hashedpassword",
                Role = "User",
                IsActive = true
            };
            string token = _jwtGenerator.GenerateToken(user);

            // Act
            var principal = _jwtGenerator.ValidateToken(token);

            // Assert
            Assert.NotNull(principal);
            Assert.Equal("testuser", principal.Identity?.Name);
        }

        [Fact]
        public void Test_ValidateToken_WithInvalidToken_ReturnsNull()
        {
            // Arrange
            string invalidToken = "invalid.token.here";

            // Act
            var principal = _jwtGenerator.ValidateToken(invalidToken);

            // Assert
            Assert.Null(principal);
        }

        [Fact]
        public void Test_GenerateToken_IncludesUserClaims()
        {
            // Arrange
            var user = new User
            {
                UserID = 42,
                Username = "claimtest",
                Email = "claim@example.com",
                PasswordHash = "hashedpassword",
                Role = "Admin",
                IsActive = true
            };

            // Act
            string token = _jwtGenerator.GenerateToken(user);
            var principal = _jwtGenerator.ValidateToken(token);

            // Assert
            Assert.NotNull(principal);
            var claims = principal.Claims.ToList();
            Assert.Contains(claims, c => c.Type == System.Security.Claims.ClaimTypes.NameIdentifier && c.Value == "42");
            Assert.Contains(claims, c => c.Type == System.Security.Claims.ClaimTypes.Name && c.Value == "claimtest");
            Assert.Contains(claims, c => c.Type == System.Security.Claims.ClaimTypes.Email && c.Value == "claim@example.com");
            Assert.Contains(claims, c => c.Type == System.Security.Claims.ClaimTypes.Role && c.Value == "Admin");
        }

        #endregion

        #region Security Attack Tests

        [Fact]
        public async Task Test_Register_WithSQLInjectionInUsername_Fails()
        {
            // Arrange
            string maliciousUsername = "admin' OR '1'='1";
            string email = "test@example.com";
            string password = "SecurePass123!";

            // Act
            var (success, message, user) = await _authService.RegisterUser(maliciousUsername, email, password);

            // Assert
            Assert.False(success);
            Assert.Null(user);
        }

        [Fact]
        public async Task Test_Register_WithXSSInUsername_Fails()
        {
            // Arrange
            string xssUsername = "<script>alert('xss')</script>";
            string email = "test@example.com";
            string password = "SecurePass123!";

            // Act
            var (success, message, user) = await _authService.RegisterUser(xssUsername, email, password);

            // Assert
            Assert.False(success);
            Assert.Null(user);
        }

        [Fact]
        public async Task Test_Login_WithSQLInjectionInUsername_Fails()
        {
            // Arrange
            string maliciousUsername = "' OR '1'='1' --";
            string password = "SomePass123!";

            // Act
            var response = await _authService.AuthenticateUser(maliciousUsername, password);

            // Assert
            Assert.False(response.Success);
            Assert.Empty(response.Token);
        }

        [Fact]
        public async Task Test_Login_WithSQLInjectionInPassword_Fails()
        {
            // Arrange - Register valid user first
            string username = "validuser";
            string email = "valid@example.com";
            string validPassword = "ValidPass123!";
            await _authService.RegisterUser(username, email, validPassword);

            // Act - Try to login with SQL injection in password
            string maliciousPassword = "' OR '1'='1' --";
            var response = await _authService.AuthenticateUser(username, maliciousPassword);

            // Assert
            Assert.False(response.Success);
            Assert.Empty(response.Token);
        }

        #endregion

        #region Role Assignment Tests

        [Fact]
        public async Task Test_RegisterUser_DefaultRoleIsUser()
        {
            // Arrange
            string username = "roletest";
            string email = "role@example.com";
            string password = "RolePass123!";

            // Act
            var (success, message, user) = await _authService.RegisterUser(username, email, password);

            // Assert
            Assert.True(success);
            Assert.NotNull(user);
            Assert.Equal("User", user.Role);
        }

        [Fact]
        public async Task Test_RegisterUser_WithAdminRole_Succeeds()
        {
            // Arrange
            string username = "adminuser";
            string email = "admin@example.com";
            string password = "AdminPass123!";

            // Act
            var (success, message, user) = await _authService.RegisterUser(username, email, password, "Admin");

            // Assert
            Assert.True(success);
            Assert.NotNull(user);
            Assert.Equal("Admin", user.Role);
        }

        [Fact]
        public async Task Test_RegisterUser_WithInvalidRole_Fails()
        {
            // Arrange
            string username = "invalidrole";
            string email = "test@example.com";
            string password = "TestPass123!";
            string invalidRole = "SuperAdmin";

            // Act
            var (success, message, user) = await _authService.RegisterUser(username, email, password, invalidRole);

            // Assert
            Assert.False(success);
            Assert.Contains("Invalid role", message);
            Assert.Null(user);
        }

        #endregion

        #region Account Status Tests

        [Fact]
        public async Task Test_NewUser_IsActiveByDefault()
        {
            // Arrange
            string username = "activetest";
            string email = "active@example.com";
            string password = "ActivePass123!";

            // Act
            var (success, message, user) = await _authService.RegisterUser(username, email, password);

            // Assert
            Assert.True(success);
            Assert.NotNull(user);
            Assert.True(user.IsActive);
        }

        [Fact]
        public async Task Test_Login_InactiveAccount_Fails()
        {
            // Arrange - Register and then deactivate
            string username = "inactivetest";
            string email = "inactive@example.com";
            string password = "InactivePass123!";
            await _authService.RegisterUser(username, email, password);

            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == username);
            user!.IsActive = false;
            await _dbContext.SaveChangesAsync();

            // Act - Try to login with inactive account
            var response = await _authService.AuthenticateUser(username, password);

            // Assert
            Assert.False(response.Success);
            Assert.Contains("inactive", response.Message.ToLower());
        }

        #endregion
    }
}
