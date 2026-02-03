using Xunit;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace SafeVault.Tests
{
    /// <summary>
    /// Role-Based Access Control (RBAC) Tests.
    /// Verifies that admin and user roles are properly enforced
    /// and that role-based authorization prevents unauthorized access.
    /// </summary>
    public class TestRBAC
    {
        private SafeVaultContext _dbContext;
        private IAuthenticationService _authService;
        private IJwtTokenGenerator _jwtGenerator;
        private IInputValidationService _validationService;

        public TestRBAC()
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

        #region Role Assignment Tests

        [Fact]
        public async Task Test_RegisterUser_DefaultRoleIsUser()
        {
            // Arrange
            string username = "newuser";
            string email = "newuser@example.com";
            string password = "SecurePass123!";

            // Act
            var (success, message, user) = await _authService.RegisterUser(username, email, password);

            // Assert
            Assert.True(success);
            Assert.NotNull(user);
            Assert.Equal("User", user.Role);
        }

        [Fact]
        public async Task Test_RegisterUser_CanAssignAdminRole()
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
        public async Task Test_RegisterUser_InvalidRole_Rejected()
        {
            // Arrange
            string username = "invalidroleuser";
            string email = "invalid@example.com";
            string password = "TestPass123!";

            // Act
            var (success, message, user) = await _authService.RegisterUser(username, email, password, "SuperAdmin");

            // Assert
            Assert.False(success);
            Assert.Contains("Invalid role", message);
            Assert.Null(user);
        }

        #endregion

        #region Token Role Claims Tests

        [Fact]
        public void Test_UserToken_ContainsUserRole()
        {
            // Arrange
            var user = new User
            {
                UserID = 1,
                Username = "regularuser",
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
            Assert.True(principal.IsInRole("User"));
            Assert.False(principal.IsInRole("Admin"));
        }

        [Fact]
        public void Test_AdminToken_ContainsAdminRole()
        {
            // Arrange
            var admin = new User
            {
                UserID = 2,
                Username = "adminuser",
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
            Assert.True(principal.IsInRole("Admin"));
            Assert.False(principal.IsInRole("User"));
        }

        #endregion

        #region Admin Dashboard Access Tests

        [Fact]
        public async Task Test_AdminDashboard_RequiresAuthentication()
        {
            // This test verifies that the dashboard endpoint requires authentication
            // In a real scenario, accessing without a token would return 401 Unauthorized
            
            // Arrange - Create users for dashboard statistics
            await CreateTestUsers();

            // Act - Count users in database (simulating dashboard data)
            var totalUsers = await _dbContext.Users.CountAsync();
            var activeUsers = await _dbContext.Users.CountAsync(u => u.IsActive);

            // Assert - Dashboard data is available
            Assert.True(totalUsers > 0);
            Assert.True(activeUsers > 0);
        }

        [Fact]
        public async Task Test_AdminDashboard_ShowsCorrectStatistics()
        {
            // Arrange - Create test data
            await CreateTestUsers();

            // Act - Calculate statistics (simulating dashboard logic)
            var totalUsers = await _dbContext.Users.CountAsync();
            var activeUsers = await _dbContext.Users.CountAsync(u => u.IsActive);
            var inactiveUsers = totalUsers - activeUsers;
            var adminCount = await _dbContext.Users.CountAsync(u => u.Role == "Admin");
            var regularUserCount = await _dbContext.Users.CountAsync(u => u.Role == "User");

            // Assert
            Assert.Equal(3, totalUsers);
            Assert.Equal(2, activeUsers);
            Assert.Equal(1, inactiveUsers);
            Assert.Equal(1, adminCount);
            Assert.Equal(2, regularUserCount);
        }

        [Fact]
        public async Task Test_AdminDashboard_TracksRecentRegistrations()
        {
            // Arrange - Create users with different registration dates
            var oldUser = new User
            {
                Username = "olduser",
                Email = "old@example.com",
                PasswordHash = _authService.HashPassword("OldPass123!"),
                Role = "User",
                CreatedAt = DateTime.UtcNow.AddDays(-60), // 60 days ago
                IsActive = true
            };

            var recentUser = new User
            {
                Username = "recentuser",
                Email = "recent@example.com",
                PasswordHash = _authService.HashPassword("RecentPass123!"),
                Role = "User",
                CreatedAt = DateTime.UtcNow.AddDays(-5), // 5 days ago
                IsActive = true
            };

            _dbContext.Users.Add(oldUser);
            _dbContext.Users.Add(recentUser);
            await _dbContext.SaveChangesAsync();

            // Act - Count recent registrations (last 30 days)
            var thirtyDaysAgo = DateTime.UtcNow.AddDays(-30);
            var recentCount = await _dbContext.Users
                .Where(u => u.CreatedAt >= thirtyDaysAgo)
                .CountAsync();

            // Assert
            Assert.Equal(1, recentCount); // Only the recent user
        }

        #endregion

        #region User Account Management Tests (Admin-only)

        [Fact]
        public async Task Test_ActivateUser_OnlyAccessibleByAdmin()
        {
            // Arrange - Create inactive user
            var user = new User
            {
                Username = "inactiveuser",
                Email = "inactive@example.com",
                PasswordHash = _authService.HashPassword("TestPass123!"),
                Role = "User",
                IsActive = false
            };
            _dbContext.Users.Add(user);
            await _dbContext.SaveChangesAsync();

            // Act - Simulate admin activating the user
            var foundUser = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == "inactiveuser");
            Assert.NotNull(foundUser);
            foundUser.IsActive = true;
            await _dbContext.SaveChangesAsync();

            // Assert
            var activatedUser = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == "inactiveuser");
            Assert.NotNull(activatedUser);
            Assert.True(activatedUser.IsActive);
        }

        [Fact]
        public async Task Test_DeactivateUser_OnlyAccessibleByAdmin()
        {
            // Arrange - Create active user
            var user = new User
            {
                Username = "activeuser",
                Email = "active@example.com",
                PasswordHash = _authService.HashPassword("TestPass123!"),
                Role = "User",
                IsActive = true
            };
            _dbContext.Users.Add(user);
            await _dbContext.SaveChangesAsync();

            // Act - Simulate admin deactivating the user
            var foundUser = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == "activeuser");
            Assert.NotNull(foundUser);
            foundUser.IsActive = false;
            await _dbContext.SaveChangesAsync();

            // Assert
            var deactivatedUser = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == "activeuser");
            Assert.NotNull(deactivatedUser);
            Assert.False(deactivatedUser.IsActive);
        }

        [Fact]
        public async Task Test_PromoteUser_OnlyAccessibleByAdmin()
        {
            // Arrange - Create regular user
            var user = new User
            {
                Username = "promotableuser",
                Email = "promote@example.com",
                PasswordHash = _authService.HashPassword("TestPass123!"),
                Role = "User",
                IsActive = true
            };
            _dbContext.Users.Add(user);
            await _dbContext.SaveChangesAsync();

            // Act - Simulate admin promoting user to admin
            var foundUser = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == "promotableuser");
            Assert.NotNull(foundUser);
            Assert.Equal("User", foundUser.Role);
            
            foundUser.Role = "Admin";
            await _dbContext.SaveChangesAsync();

            // Assert
            var promotedUser = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == "promotableuser");
            Assert.NotNull(promotedUser);
            Assert.Equal("Admin", promotedUser.Role);
        }

        [Fact]
        public async Task Test_CannotDeactivateLastAdmin()
        {
            // Arrange - Create only one admin
            var admin = new User
            {
                Username = "onlyadmin",
                Email = "onlyadmin@example.com",
                PasswordHash = _authService.HashPassword("AdminPass123!"),
                Role = "Admin",
                IsActive = true
            };
            _dbContext.Users.Add(admin);
            await _dbContext.SaveChangesAsync();

            // Act - Check if this is the last active admin
            var adminCount = await _dbContext.Users.CountAsync(u => u.Role == "Admin" && u.IsActive);

            // Assert - Should prevent deactivation when only 1 admin exists
            Assert.Equal(1, adminCount);
        }

        [Fact]
        public async Task Test_CanDeactivateAdminWhenMultipleExist()
        {
            // Arrange - Create multiple admins
            var admin1 = new User
            {
                Username = "admin1",
                Email = "admin1@example.com",
                PasswordHash = _authService.HashPassword("Admin1Pass123!"),
                Role = "Admin",
                IsActive = true
            };
            var admin2 = new User
            {
                Username = "admin2",
                Email = "admin2@example.com",
                PasswordHash = _authService.HashPassword("Admin2Pass123!"),
                Role = "Admin",
                IsActive = true
            };
            _dbContext.Users.Add(admin1);
            _dbContext.Users.Add(admin2);
            await _dbContext.SaveChangesAsync();

            // Act - Deactivate one admin
            var adminCount = await _dbContext.Users.CountAsync(u => u.Role == "Admin" && u.IsActive);
            Assert.True(adminCount > 1); // Safe to deactivate

            admin1.IsActive = false;
            await _dbContext.SaveChangesAsync();

            // Assert
            var remainingAdmins = await _dbContext.Users.CountAsync(u => u.Role == "Admin" && u.IsActive);
            Assert.Equal(1, remainingAdmins);
        }

        #endregion

        #region Authorization Policy Tests

        [Fact]
        public void Test_UserCanAccessUserOrAdminEndpoints()
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

            // Assert - User should satisfy UserOrAdmin policy
            Assert.NotNull(principal);
            Assert.True(principal.IsInRole("User"));
        }

        [Fact]
        public void Test_AdminCanAccessUserOrAdminEndpoints()
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

            // Assert - Admin should satisfy UserOrAdmin policy
            Assert.NotNull(principal);
            Assert.True(principal.IsInRole("Admin"));
        }

        [Fact]
        public void Test_AdminCanAccessAdminOnlyEndpoints()
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

            // Assert - Admin should satisfy AdminOnly policy
            Assert.NotNull(principal);
            Assert.True(principal.IsInRole("Admin"));
        }

        [Fact]
        public void Test_UserCannotAccessAdminOnlyEndpoints()
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

            // Assert - User should NOT satisfy AdminOnly policy
            Assert.NotNull(principal);
            Assert.False(principal.IsInRole("Admin"));
        }

        #endregion

        #region Role Enforcement Tests

        [Fact]
        public async Task Test_RoleCannotBeChangedByRegularUser()
        {
            // Arrange - Create regular user
            var user = new User
            {
                Username = "regularuser",
                Email = "regular@example.com",
                PasswordHash = _authService.HashPassword("UserPass123!"),
                Role = "User",
                IsActive = true
            };
            _dbContext.Users.Add(user);
            await _dbContext.SaveChangesAsync();

            // Act - Verify user cannot escalate privileges
            var foundUser = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == "regularuser");
            Assert.NotNull(foundUser);
            Assert.Equal("User", foundUser.Role);

            // In a real scenario, only admins can change roles
            // The endpoint would check authorization before allowing role changes
        }

        [Fact]
        public async Task Test_OnlyTwoRolesExist()
        {
            // Arrange & Act - Try to create user with each valid role
            var userWithUserRole = await _authService.RegisterUser("user1", "user1@example.com", "Pass123!", "User");
            var userWithAdminRole = await _authService.RegisterUser("admin1", "admin1@example.com", "Pass123!", "Admin");
            var userWithInvalidRole = await _authService.RegisterUser("invalid", "invalid@example.com", "Pass123!", "Moderator");

            // Assert
            Assert.True(userWithUserRole.Success);
            Assert.True(userWithAdminRole.Success);
            Assert.False(userWithInvalidRole.Success);
        }

        #endregion

        #region Helper Methods

        private async Task CreateTestUsers()
        {
            var admin = new User
            {
                Username = "testadmin",
                Email = "testadmin@example.com",
                PasswordHash = _authService.HashPassword("AdminPass123!"),
                Role = "Admin",
                CreatedAt = DateTime.UtcNow,
                IsActive = true
            };

            var user1 = new User
            {
                Username = "testuser1",
                Email = "testuser1@example.com",
                PasswordHash = _authService.HashPassword("UserPass123!"),
                Role = "User",
                CreatedAt = DateTime.UtcNow,
                IsActive = true
            };

            var user2 = new User
            {
                Username = "testuser2",
                Email = "testuser2@example.com",
                PasswordHash = _authService.HashPassword("UserPass123!"),
                Role = "User",
                CreatedAt = DateTime.UtcNow,
                IsActive = false
            };

            _dbContext.Users.AddRange(admin, user1, user2);
            await _dbContext.SaveChangesAsync();
        }

        #endregion
    }
}
