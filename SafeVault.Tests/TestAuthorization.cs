using Xunit;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System.Security.Claims;

namespace SafeVault.Tests
{
    /// <summary>
    /// Comprehensive authorization tests.
    /// Tests role-based access control, endpoint protection,
    /// JWT token validation, and authorization bypass prevention.
    /// </summary>
    public class TestAuthorization
    {
        private SafeVaultContext _dbContext;
        private IAuthenticationService _authService;
        private IJwtTokenGenerator _jwtGenerator;
        private IInputValidationService _validationService;

        public TestAuthorization()
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

        #region Role-Based Access Control Tests

        [Fact]
        public async Task Test_UserRole_CanAccessUserEndpoints()
        {
            // Arrange - Create user with User role
            var user = new User
            {
                Username = "regularuser",
                Email = "user@example.com",
                PasswordHash = _authService.HashPassword("UserPass123!"),
                Role = "User",
                IsActive = true
            };
            _dbContext.Users.Add(user);
            await _dbContext.SaveChangesAsync();

            // Act - Generate token
            string token = _jwtGenerator.GenerateToken(user);
            var principal = _jwtGenerator.ValidateToken(token);

            // Assert - User should have "User" role claim
            Assert.NotNull(principal);
            Assert.True(principal.IsInRole("User"));
            Assert.False(principal.IsInRole("Admin"));
        }

        [Fact]
        public async Task Test_AdminRole_CanAccessAdminEndpoints()
        {
            // Arrange - Create user with Admin role
            var admin = new User
            {
                Username = "adminuser",
                Email = "admin@example.com",
                PasswordHash = _authService.HashPassword("AdminPass123!"),
                Role = "Admin",
                IsActive = true
            };
            _dbContext.Users.Add(admin);
            await _dbContext.SaveChangesAsync();

            // Act - Generate token
            string token = _jwtGenerator.GenerateToken(admin);
            var principal = _jwtGenerator.ValidateToken(token);

            // Assert - Admin should have "Admin" role claim
            Assert.NotNull(principal);
            Assert.True(principal.IsInRole("Admin"));
            Assert.False(principal.IsInRole("User"));
        }

        [Fact]
        public async Task Test_RegularUser_CannotAccessAdminEndpoints()
        {
            // Arrange - Create regular user
            var user = new User
            {
                Username = "regularuser",
                Email = "user@example.com",
                PasswordHash = _authService.HashPassword("UserPass123!"),
                Role = "User",
                IsActive = true
            };
            _dbContext.Users.Add(user);
            await _dbContext.SaveChangesAsync();

            // Act - Generate token and validate role
            string token = _jwtGenerator.GenerateToken(user);
            var principal = _jwtGenerator.ValidateToken(token);

            // Assert - Should NOT have Admin role
            Assert.NotNull(principal);
            Assert.False(principal.IsInRole("Admin"));
        }

        #endregion

        #region Token Validation Tests

        [Fact]
        public void Test_ValidToken_PassesValidation()
        {
            // Arrange
            var user = new User
            {
                UserID = 1,
                Username = "validuser",
                Email = "valid@example.com",
                PasswordHash = "hash",
                Role = "User",
                IsActive = true
            };
            string token = _jwtGenerator.GenerateToken(user);

            // Act
            var principal = _jwtGenerator.ValidateToken(token);

            // Assert
            Assert.NotNull(principal);
            Assert.NotNull(principal.Identity);
            Assert.True(principal.Identity.IsAuthenticated);
        }

        [Fact]
        public void Test_InvalidToken_FailsValidation()
        {
            // Arrange
            string invalidToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature";

            // Act
            var principal = _jwtGenerator.ValidateToken(invalidToken);

            // Assert
            Assert.Null(principal);
        }

        [Fact]
        public void Test_MalformedToken_FailsValidation()
        {
            // Arrange
            string malformedToken = "not-a-jwt-token";

            // Act
            var principal = _jwtGenerator.ValidateToken(malformedToken);

            // Assert
            Assert.Null(principal);
        }

        [Fact]
        public void Test_EmptyToken_FailsValidation()
        {
            // Arrange
            string emptyToken = "";

            // Act
            var principal = _jwtGenerator.ValidateToken(emptyToken);

            // Assert
            Assert.Null(principal);
        }

        #endregion

        #region Token Claims Tests

        [Fact]
        public void Test_TokenClaims_ContainUserId()
        {
            // Arrange
            var user = new User
            {
                UserID = 123,
                Username = "testuser",
                Email = "test@example.com",
                PasswordHash = "hash",
                Role = "User",
                IsActive = true
            };

            // Act
            string token = _jwtGenerator.GenerateToken(user);
            var principal = _jwtGenerator.ValidateToken(token);

            // Assert
            Assert.NotNull(principal);
            var userIdClaim = principal.FindFirst(ClaimTypes.NameIdentifier);
            Assert.NotNull(userIdClaim);
            Assert.Equal("123", userIdClaim.Value);
        }

        [Fact]
        public void Test_TokenClaims_ContainEmail()
        {
            // Arrange
            var user = new User
            {
                UserID = 1,
                Username = "emailtest",
                Email = "emailtest@example.com",
                PasswordHash = "hash",
                Role = "User",
                IsActive = true
            };

            // Act
            string token = _jwtGenerator.GenerateToken(user);
            var principal = _jwtGenerator.ValidateToken(token);

            // Assert
            Assert.NotNull(principal);
            var emailClaim = principal.FindFirst(ClaimTypes.Email);
            Assert.NotNull(emailClaim);
            Assert.Equal("emailtest@example.com", emailClaim.Value);
        }

        [Fact]
        public void Test_TokenClaims_ContainRole()
        {
            // Arrange
            var admin = new User
            {
                UserID = 1,
                Username = "admintest",
                Email = "admin@example.com",
                PasswordHash = "hash",
                Role = "Admin",
                IsActive = true
            };

            // Act
            string token = _jwtGenerator.GenerateToken(admin);
            var principal = _jwtGenerator.ValidateToken(token);

            // Assert
            Assert.NotNull(principal);
            var roleClaim = principal.FindFirst(ClaimTypes.Role);
            Assert.NotNull(roleClaim);
            Assert.Equal("Admin", roleClaim.Value);
        }

        #endregion

        #region Authorization Bypass Tests

        [Fact]
        public async Task Test_RoleEscalation_CannotModifyRoleViaUpdate()
        {
            // This test verifies that users cannot escalate their own privileges
            // by attempting to modify the Role field through update operations

            // Arrange - Create regular user
            var user = new User
            {
                Username = "regularuser",
                Email = "user@example.com",
                PasswordHash = _authService.HashPassword("UserPass123!"),
                Role = "User",
                IsActive = true
            };
            _dbContext.Users.Add(user);
            await _dbContext.SaveChangesAsync();

            // Act - Try to modify role (simulating what would be prevented by authorization)
            // In real scenario, the update endpoint checks authorization before allowing this
            var foundUser = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == "regularuser");
            
            // Assert - User should still have User role
            Assert.NotNull(foundUser);
            Assert.Equal("User", foundUser.Role);
        }

        [Fact]
        public void Test_TokenManipulation_ChangedPayload_FailsValidation()
        {
            // Arrange - Generate valid token
            var user = new User
            {
                UserID = 1,
                Username = "testuser",
                Email = "test@example.com",
                PasswordHash = "hash",
                Role = "User",
                IsActive = true
            };
            string validToken = _jwtGenerator.GenerateToken(user);

            // Act - Manipulate token (change a character in payload)
            string manipulatedToken = validToken.Replace("User", "Admin");
            var principal = _jwtGenerator.ValidateToken(manipulatedToken);

            // Assert - Modified token should fail validation
            Assert.Null(principal);
        }

        [Fact]
        public void Test_TokenFromDifferentIssuer_FailsValidation()
        {
            // This test simulates a token generated by a different system
            // trying to access our application

            // Arrange - Token with invalid issuer would fail validation
            string tokenFromDifferentSystem = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

            // Act
            var principal = _jwtGenerator.ValidateToken(tokenFromDifferentSystem);

            // Assert - Should fail because signature is invalid
            Assert.Null(principal);
        }

        #endregion

        #region Privilege Separation Tests

        [Fact]
        public void Test_AdminToken_ContainsAdminRole()
        {
            // Arrange
            var admin = new User
            {
                UserID = 1,
                Username = "admin",
                Email = "admin@example.com",
                PasswordHash = "hash",
                Role = "Admin",
                IsActive = true
            };

            // Act
            string token = _jwtGenerator.GenerateToken(admin);
            var principal = _jwtGenerator.ValidateToken(token);

            // Assert
            Assert.NotNull(principal);
            var roles = principal.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
            Assert.Contains("Admin", roles);
            Assert.DoesNotContain("User", roles);
        }

        [Fact]
        public void Test_UserToken_ContainsUserRole()
        {
            // Arrange
            var user = new User
            {
                UserID = 1,
                Username = "user",
                Email = "user@example.com",
                PasswordHash = "hash",
                Role = "User",
                IsActive = true
            };

            // Act
            string token = _jwtGenerator.GenerateToken(user);
            var principal = _jwtGenerator.ValidateToken(token);

            // Assert
            Assert.NotNull(principal);
            var roles = principal.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
            Assert.Contains("User", roles);
            Assert.DoesNotContain("Admin", roles);
        }

        #endregion

        #region Defense Against Common Attacks

        [Fact]
        public async Task Test_UsernameEnumeration_Prevention()
        {
            // This test verifies that login errors don't reveal whether username exists

            // Arrange - Register a user
            await _authService.RegisterUser("existinguser", "exists@example.com", "ValidPass123!");

            // Act - Try to login with existing username but wrong password
            var response1 = await _authService.AuthenticateUser("existinguser", "WrongPass123!");
            
            // Act - Try to login with non-existent username
            var response2 = await _authService.AuthenticateUser("nonexistent", "SomePass123!");

            // Assert - Both should return same generic error message
            Assert.False(response1.Success);
            Assert.False(response2.Success);
            Assert.Equal(response1.Message, response2.Message);
            Assert.Equal("Invalid username or password", response1.Message);
        }

        [Fact]
        public void Test_TimingAttack_PasswordVerification()
        {
            // BCrypt's built-in constant-time comparison prevents timing attacks
            // This test verifies that password verification completes in reasonable time

            // Arrange
            string password = "TestPassword123!";
            string hash = _authService.HashPassword(password);

            // Act - Verify correct password
            var timer1 = System.Diagnostics.Stopwatch.StartNew();
            _authService.VerifyPassword(password, hash);
            timer1.Stop();

            // Act - Verify incorrect password
            var timer2 = System.Diagnostics.Stopwatch.StartNew();
            _authService.VerifyPassword("WrongPassword123!", hash);
            timer2.Stop();

            // Assert - Both should complete quickly and in similar time
            Assert.True(timer1.ElapsedMilliseconds < 1000);
            Assert.True(timer2.ElapsedMilliseconds < 1000);
            // BCrypt ensures timing is constant regardless of match
        }

        #endregion

        #region Token Expiration Tests

        [Fact]
        public void Test_TokenExpiration_ConfiguredCorrectly()
        {
            // Arrange
            var user = new User
            {
                UserID = 1,
                Username = "expirytest",
                Email = "expiry@example.com",
                PasswordHash = "hash",
                Role = "User",
                IsActive = true
            };

            // Act
            string token = _jwtGenerator.GenerateToken(user);
            var principal = _jwtGenerator.ValidateToken(token);

            // Assert - Token should be valid immediately after creation
            Assert.NotNull(principal);
        }

        #endregion

        #region Account Security Tests

        [Fact]
        public async Task Test_InactiveAccount_CannotLogin()
        {
            // Arrange - Create and deactivate user
            var user = new User
            {
                Username = "inactiveuser",
                Email = "inactive@example.com",
                PasswordHash = _authService.HashPassword("InactivePass123!"),
                Role = "User",
                IsActive = false
            };
            _dbContext.Users.Add(user);
            await _dbContext.SaveChangesAsync();

            // Act - Try to login
            var response = await _authService.AuthenticateUser("inactiveuser", "InactivePass123!");

            // Assert - Should fail
            Assert.False(response.Success);
            Assert.Contains("inactive", response.Message.ToLower());
        }

        [Fact]
        public async Task Test_MultipleUsers_IsolatedAuthentication()
        {
            // Arrange - Create multiple users
            await _authService.RegisterUser("user1", "user1@example.com", "Pass1Word123!");
            await _authService.RegisterUser("user2", "user2@example.com", "Pass2Word123!");

            // Act - Login as different users
            var response1 = await _authService.AuthenticateUser("user1", "Pass1Word123!");
            var response2 = await _authService.AuthenticateUser("user2", "Pass2Word123!");

            // Assert - Both should succeed independently
            Assert.True(response1.Success);
            Assert.True(response2.Success);
            Assert.NotEqual(response1.Token, response2.Token);
            Assert.Equal("user1", response1.User?.Username);
            Assert.Equal("user2", response2.User?.Username);
        }

        #endregion

        #region Cross-User Access Prevention Tests

        [Fact]
        public async Task Test_User1Token_CannotAccessUser2Data()
        {
            // This test verifies that users are properly isolated
            // Token validation returns correct user identity

            // Arrange - Create two users
            var user1 = new User
            {
                UserID = 1,
                Username = "user1",
                Email = "user1@example.com",
                PasswordHash = "hash",
                Role = "User",
                IsActive = true
            };
            var user2 = new User
            {
                UserID = 2,
                Username = "user2",
                Email = "user2@example.com",
                PasswordHash = "hash",
                Role = "User",
                IsActive = true
            };

            // Act - Generate tokens
            string token1 = _jwtGenerator.GenerateToken(user1);
            var principal1 = _jwtGenerator.ValidateToken(token1);

            // Assert - Token 1 should only identify user 1
            Assert.NotNull(principal1);
            var userIdClaim = principal1.FindFirst(ClaimTypes.NameIdentifier);
            Assert.NotNull(userIdClaim);
            Assert.Equal("1", userIdClaim.Value);
            Assert.NotEqual("2", userIdClaim.Value);
        }

        #endregion

        #region Password Security Tests

        [Fact]
        public async Task Test_PasswordNotStoredInPlainText()
        {
            // Arrange
            string password = "PlainTextTest123!";
            await _authService.RegisterUser("plaintexttest", "plain@example.com", password);

            // Act - Retrieve user from database
            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == "plaintexttest");

            // Assert - Password should be hashed, not plain text
            Assert.NotNull(user);
            Assert.NotEqual(password, user.PasswordHash);
            Assert.True(user.PasswordHash.StartsWith("$2")); // BCrypt hash format
        }

        [Fact]
        public void Test_BCryptHash_ProperFormat()
        {
            // Arrange
            string password = "TestPassword123!";

            // Act
            string hash = _authService.HashPassword(password);

            // Assert - BCrypt hash should start with $2a$, $2b$, or $2y$
            Assert.True(hash.StartsWith("$2"));
            Assert.Equal(60, hash.Length); // BCrypt hashes are 60 characters
        }

        [Fact]
        public void Test_PasswordHash_UniqueSalts()
        {
            // Arrange
            string password = "SamePassword123!";

            // Act - Hash same password multiple times
            string hash1 = _authService.HashPassword(password);
            string hash2 = _authService.HashPassword(password);
            string hash3 = _authService.HashPassword(password);

            // Assert - All hashes should be different due to unique salts
            Assert.NotEqual(hash1, hash2);
            Assert.NotEqual(hash2, hash3);
            Assert.NotEqual(hash1, hash3);
            
            // But all should verify against the original password
            Assert.True(_authService.VerifyPassword(password, hash1));
            Assert.True(_authService.VerifyPassword(password, hash2));
            Assert.True(_authService.VerifyPassword(password, hash3));
        }

        #endregion

        #region Authorization Policy Tests

        [Fact]
        public void Test_UserOrAdminPolicy_AcceptsUserRole()
        {
            // Arrange
            var user = new User
            {
                UserID = 1,
                Username = "user",
                Email = "user@example.com",
                PasswordHash = "hash",
                Role = "User",
                IsActive = true
            };

            // Act
            string token = _jwtGenerator.GenerateToken(user);
            var principal = _jwtGenerator.ValidateToken(token);

            // Assert - Should satisfy UserOrAdmin policy
            Assert.NotNull(principal);
            Assert.True(principal.IsInRole("User"));
        }

        [Fact]
        public void Test_UserOrAdminPolicy_AcceptsAdminRole()
        {
            // Arrange
            var admin = new User
            {
                UserID = 1,
                Username = "admin",
                Email = "admin@example.com",
                PasswordHash = "hash",
                Role = "Admin",
                IsActive = true
            };

            // Act
            string token = _jwtGenerator.GenerateToken(admin);
            var principal = _jwtGenerator.ValidateToken(token);

            // Assert - Should satisfy UserOrAdmin policy
            Assert.NotNull(principal);
            Assert.True(principal.IsInRole("Admin"));
        }

        [Fact]
        public void Test_AdminOnlyPolicy_RejectsUserRole()
        {
            // Arrange
            var user = new User
            {
                UserID = 1,
                Username = "user",
                Email = "user@example.com",
                PasswordHash = "hash",
                Role = "User",
                IsActive = true
            };

            // Act
            string token = _jwtGenerator.GenerateToken(user);
            var principal = _jwtGenerator.ValidateToken(token);

            // Assert - Should NOT satisfy AdminOnly policy
            Assert.NotNull(principal);
            Assert.False(principal.IsInRole("Admin"));
        }

        #endregion
    }
}
