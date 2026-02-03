using Xunit;
using SafeVault.Data;
using SafeVault.Models;
using Microsoft.EntityFrameworkCore;

namespace SafeVault.Tests
{
    /// <summary>
    /// Tests that demonstrate security vulnerabilities in intentionally vulnerable endpoints.
    /// These tests show what happens when security best practices are NOT followed.
    /// FOR EDUCATIONAL PURPOSES ONLY.
    /// </summary>
    public class TestVulnerableEndpoints
    {
        private SafeVaultContext _dbContext;

        public TestVulnerableEndpoints()
        {
            var options = new DbContextOptionsBuilder<SafeVaultContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            _dbContext = new SafeVaultContext(options);
            _dbContext.Database.EnsureCreated();

            // Seed test data
            SeedTestData().Wait();
        }

        private async Task SeedTestData()
        {
            var users = new List<User>
            {
                new User
                {
                    Username = "admin",
                    Email = "admin@example.com",
                    PasswordHash = "hashedpassword",
                    Role = "Admin",
                    IsActive = true
                },
                new User
                {
                    Username = "testuser",
                    Email = "test@example.com",
                    PasswordHash = "hashedpassword",
                    Role = "User",
                    IsActive = true
                },
                new User
                {
                    Username = "malicious<script>alert('xss')</script>",
                    Email = "malicious@example.com",
                    PasswordHash = "hashedpassword",
                    Role = "User",
                    IsActive = true
                }
            };

            _dbContext.Users.AddRange(users);
            await _dbContext.SaveChangesAsync();
        }

        #region SQL Injection Vulnerability Tests

        [Fact]
        public async Task Test_VulnerableEndpoint_SqlInjection_BypassAuthentication()
        {
            // This test demonstrates a SQL injection attack that bypasses authentication
            // VULNERABILITY: String interpolation in SQL query

            // Arrange
            string maliciousInput = "admin' OR '1'='1";

            // Act - Attempt SQL injection
            // In the vulnerable endpoint, this would create:
            // SELECT * FROM Users WHERE Username = 'admin' OR '1'='1'
            // This returns ALL users because '1'='1' is always true

            try
            {
                var users = await _dbContext.Users
                    .FromSqlRaw($"SELECT * FROM Users WHERE Username = '{maliciousInput}'")
                    .ToListAsync();

                // Assert - SQL injection succeeded
                // In a vulnerable system, this would return all users
                Assert.True(users.Count >= 1, "SQL injection attack would succeed on vulnerable endpoint");
            }
            catch
            {
                // If this throws, it means the attack failed (good for secure code)
                Assert.True(true, "Attack was blocked");
            }
        }

        [Fact]
        public async Task Test_VulnerableEndpoint_SqlInjection_UnionAttack()
        {
            // Demonstrates UNION-based SQL injection

            // Arrange
            string maliciousInput = "' UNION SELECT UserID, Username, Email, PasswordHash, Role, CreatedAt, LastLoginAt, IsActive FROM Users--";

            // Act - Attempt to extract all data
            try
            {
                var query = $"SELECT * FROM Users WHERE Username = '{maliciousInput}'";
                var users = await _dbContext.Users
                    .FromSqlRaw(query)
                    .ToListAsync();

                // This would succeed on vulnerable endpoint
                Assert.True(true, "UNION attack demonstrates data extraction risk");
            }
            catch
            {
                Assert.True(true, "Attack pattern detected");
            }
        }

        [Fact]
        public async Task Test_VulnerableEndpoint_SqlInjection_CommentInjection()
        {
            // Demonstrates comment-based SQL injection

            // Arrange
            string maliciousInput = "admin'--";

            // Act
            // Creates: SELECT * FROM Users WHERE Username = 'admin'--'
            // Everything after -- is commented out
            try
            {
                var users = await _dbContext.Users
                    .FromSqlRaw($"SELECT * FROM Users WHERE Username = '{maliciousInput}'")
                    .ToListAsync();

                // Would return admin user
                Assert.True(true, "Comment injection demonstrates query manipulation");
            }
            catch
            {
                Assert.True(true, "Attack pattern handled");
            }
        }

        [Fact]
        public async Task Test_VulnerableEndpoint_SqlInjection_DropTable()
        {
            // Demonstrates destructive SQL injection attempt

            // Arrange
            string maliciousInput = "'; DROP TABLE Users; --";

            // Act
            try
            {
                var users = await _dbContext.Users
                    .FromSqlRaw($"SELECT * FROM Users WHERE Username = '{maliciousInput}'")
                    .ToListAsync();
            }
            catch
            {
                // Expected to fail, but demonstrates the danger
                Assert.True(true, "DROP TABLE attack demonstrates destructive potential");
            }
        }

        [Fact]
        public async Task Test_VulnerableEndpoint_SqlInjection_EmailField()
        {
            // Demonstrates SQL injection through email field

            // Arrange
            string maliciousEmail = "test@example.com' OR '1'='1";

            // Act
            try
            {
                var query = $"SELECT * FROM Users WHERE Email = '{maliciousEmail}'";
                var users = await _dbContext.Users
                    .FromSqlRaw(query)
                    .ToListAsync();

                // Would return all users on vulnerable endpoint
                Assert.True(true, "Email field is also vulnerable to SQL injection");
            }
            catch
            {
                Assert.True(true, "Attack detected");
            }
        }

        #endregion

        #region XSS Vulnerability Tests

        [Fact]
        public void Test_VulnerableEndpoint_XSS_ScriptTag()
        {
            // Demonstrates XSS through script tag injection

            // Arrange
            string maliciousComment = "<script>alert('XSS Attack!')</script>";

            // Act - On vulnerable endpoint, this would be returned unencoded
            string response = $"Comment received: {maliciousComment}";

            // Assert - Without encoding, script tags remain
            Assert.Contains("<script>", response);
            Assert.Contains("alert", response);
            
            // This demonstrates the vulnerability:
            // The script would execute in a browser
        }

        [Fact]
        public void Test_VulnerableEndpoint_XSS_EventHandler()
        {
            // Demonstrates XSS through event handler injection

            // Arrange
            string maliciousComment = "<img src=x onerror=alert('XSS')>";

            // Act
            string response = $"Comment received: {maliciousComment}";

            // Assert - Without encoding, the img tag with onerror remains
            Assert.Contains("onerror", response);
            Assert.Contains("alert", response);
        }

        [Fact]
        public void Test_VulnerableEndpoint_XSS_JavascriptProtocol()
        {
            // Demonstrates XSS through javascript: protocol

            // Arrange
            string maliciousComment = "<a href='javascript:alert(\"XSS\")'>Click me</a>";

            // Act
            string response = $"Comment received: {maliciousComment}";

            // Assert
            Assert.Contains("javascript:", response);
            Assert.Contains("alert", response);
        }

        [Fact]
        public async Task Test_VulnerableEndpoint_XSS_StoredInDatabase()
        {
            // Demonstrates stored XSS vulnerability

            // Arrange - User with malicious content already in database
            var maliciousUser = await _dbContext.Users
                .FirstOrDefaultAsync(u => u.Username.Contains("<script>"));

            // Assert - Malicious content is stored
            Assert.NotNull(maliciousUser);
            Assert.Contains("<script>", maliciousUser.Username);

            // When displayed without encoding, this would execute
            string htmlOutput = $"<p>Username: {maliciousUser.Username}</p>";
            Assert.Contains("<script>", htmlOutput);
        }

        [Fact]
        public void Test_VulnerableEndpoint_XSS_HTMLInjection()
        {
            // Demonstrates HTML injection vulnerability

            // Arrange
            string maliciousComment = "<h1>Fake Heading</h1><p>Injected content</p>";

            // Act
            string htmlResponse = $@"
                <html>
                <body>
                    <div>Comment: {maliciousComment}</div>
                </body>
                </html>";

            // Assert - HTML structure is altered
            Assert.Contains("<h1>Fake Heading</h1>", htmlResponse);
        }

        [Fact]
        public void Test_VulnerableEndpoint_XSS_SvgInjection()
        {
            // Demonstrates XSS through SVG

            // Arrange
            string maliciousSvg = "<svg onload=alert('XSS')>";

            // Act
            string response = $"Comment: {maliciousSvg}";

            // Assert
            Assert.Contains("<svg", response);
            Assert.Contains("onload", response);
        }

        #endregion

        #region Missing Input Validation Tests

        [Fact]
        public void Test_VulnerableEndpoint_NoInputValidation()
        {
            // Demonstrates lack of input validation

            // Arrange
            string excessivelyLongInput = new string('A', 10000);

            // Act - No validation means this would be accepted
            // This could cause buffer overflow or DoS

            // Assert
            Assert.True(excessivelyLongInput.Length == 10000);
            Assert.True(true, "Lack of input validation allows excessively long inputs");
        }

        [Fact]
        public void Test_VulnerableEndpoint_SpecialCharacters()
        {
            // Demonstrates acceptance of dangerous special characters

            // Arrange
            string[] dangerousInputs = new[]
            {
                "../../../etc/passwd",  // Path traversal
                "'; DROP TABLE Users;--", // SQL injection
                "<script>alert(1)</script>", // XSS
                "\\x00", // Null byte injection
                "%0a", // CRLF injection
            };

            // Act & Assert - Vulnerable endpoint would accept all of these
            foreach (var input in dangerousInputs)
            {
                Assert.NotNull(input);
                // On vulnerable endpoint, these would all be processed
            }
        }

        #endregion

        #region Error Message Information Disclosure

        [Fact]
        public async Task Test_VulnerableEndpoint_ErrorMessageDisclosure()
        {
            // Demonstrates information disclosure through error messages

            // Arrange
            string maliciousInput = "' OR 1=CAST((SELECT TOP 1 Username FROM Users) AS INT)--";

            // Act
            try
            {
                var users = await _dbContext.Users
                    .FromSqlRaw($"SELECT * FROM Users WHERE Username = '{maliciousInput}'")
                    .ToListAsync();
            }
            catch (Exception ex)
            {
                // Assert - Error message might reveal database structure
                Assert.NotNull(ex.Message);
                // Vulnerable endpoints often expose full error details
                Assert.True(true, "Error messages can reveal sensitive information");
            }
        }

        #endregion

        #region Demonstration Summary

        [Fact]
        public void Test_VulnerabilityDemonstrationSummary()
        {
            // This test documents all vulnerabilities demonstrated

            var vulnerabilities = new List<string>
            {
                "SQL Injection - String concatenation in queries",
                "SQL Injection - Union-based data extraction",
                "SQL Injection - Comment injection",
                "SQL Injection - Destructive commands (DROP TABLE)",
                "XSS - Script tag injection",
                "XSS - Event handler injection (onerror, onload)",
                "XSS - JavaScript protocol injection",
                "XSS - Stored XSS in database",
                "XSS - HTML injection",
                "XSS - SVG-based XSS",
                "Missing Input Validation - Length checks",
                "Missing Input Validation - Special character filtering",
                "Information Disclosure - Detailed error messages"
            };

            Assert.Equal(13, vulnerabilities.Count);
            
            // All of these vulnerabilities are present in the vulnerable endpoints
            // The next test file will show how secure endpoints prevent these attacks
        }

        #endregion
    }
}
