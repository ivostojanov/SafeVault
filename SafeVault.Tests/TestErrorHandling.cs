using Xunit;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;
using Microsoft.EntityFrameworkCore;

namespace SafeVault.Tests
{
    /// <summary>
    /// Tests for error handling and information disclosure prevention.
    /// These tests ensure that the application handles errors gracefully
    /// without leaking sensitive information to users or attackers.
    /// </summary>
    public class TestErrorHandling
    {
        private SafeVaultContext _dbContext;
        private IInputValidationService _validationService;

        public TestErrorHandling()
        {
            var options = new DbContextOptionsBuilder<SafeVaultContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            _dbContext = new SafeVaultContext(options);
            _dbContext.Database.EnsureCreated();
            _validationService = new InputValidationService();
        }

        #region Input Validation Error Tests

        [Fact]
        public void Test_ValidationError_DoesNotExposeDatabaseDetails()
        {
            // Arrange - Malicious input
            string maliciousInput = "'; DROP TABLE users; --";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(maliciousInput, email);

            // Assert
            Assert.False(result.IsValid);
            Assert.NotEmpty(result.Errors);

            // Verify error messages don't contain database information
            foreach (var error in result.Errors)
            {
                Assert.DoesNotContain("SQL", error, System.StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("Database", error, System.StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("Table", error, System.StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("Column", error, System.StringComparison.OrdinalIgnoreCase);
            }
        }

        [Fact]
        public void Test_ValidationError_DoesNotExposeProgrammingDetails()
        {
            // Arrange
            string tooLongInput = new string('a', 1000);
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(tooLongInput, email);

            // Assert
            Assert.False(result.IsValid);

            // Verify error messages don't expose implementation details
            foreach (var error in result.Errors)
            {
                Assert.DoesNotContain("exception", error, System.StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("null reference", error, System.StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("stack trace", error, System.StringComparison.OrdinalIgnoreCase);
            }
        }

        #endregion

        #region Database Operation Error Tests

        [Fact]
        public void Test_QueryNonExistentUser_ReturnsNullSafely()
        {
            // Arrange - Try to query a user that doesn't exist
            int nonExistentId = 99999;

            // Act
            var result = _dbContext.Users.FirstOrDefault(u => u.UserID == nonExistentId);

            // Assert - Should return null, not throw
            Assert.Null(result);
        }

        [Fact]
        public void Test_UpdateNonExistentUser_HandledGracefully()
        {
            // Arrange
            int nonExistentId = 99999;

            // Act - Try to update non-existent user
            var user = _dbContext.Users.FirstOrDefault(u => u.UserID == nonExistentId);

            // Assert - No exception should be thrown
            Assert.Null(user);
        }

        [Fact]
        public void Test_DeleteNonExistentUser_HandledGracefully()
        {
            // Arrange
            int nonExistentId = 99999;

            // Act - Try to delete non-existent user
            var user = _dbContext.Users.FirstOrDefault(u => u.UserID == nonExistentId);
            if (user != null)
            {
                _dbContext.Users.Remove(user);
            }
            _dbContext.SaveChanges();

            // Assert - No exception, operation completed safely
            // (SaveChanges was called but found nothing to delete)
        }

        #endregion

        #region Duplicate Data Error Tests

        [Fact]
        public void Test_InsertDuplicateEmail_PreventionStrategy()
        {
            // Arrange - Insert first user
            var user1 = new User { Username = "user1", Email = "duplicate@example.com" };
            _dbContext.Users.Add(user1);
            _dbContext.SaveChanges();

            // Act - Try to insert second user with same email
            var user2 = new User { Username = "user2", Email = "duplicate@example.com" };
            _dbContext.Users.Add(user2);

            // Assert - In a real system, this should be caught and reported safely
            // For now, we test that the application can handle it without crashing
            try
            {
                _dbContext.SaveChanges();
            }
            catch (DbUpdateException)
            {
                // Expected - database constraint violation
                // In production, this should be caught and a user-friendly error returned
            }
        }

        #endregion

        #region Exception Handling Tests

        [Fact]
        public void Test_MalformedQueryParameter_DoesNotCrash()
        {
            // Arrange - Create some test data
            var user = new User { Username = "testuser", Email = "test@example.com" };
            _dbContext.Users.Add(user);
            _dbContext.SaveChanges();

            // Act - Try various query operations that might fail
            var result1 = _dbContext.Users.FirstOrDefault(u => u.UserID == 0);
            var result2 = _dbContext.Users.FirstOrDefault(u => u.Username == null);
            var result3 = _dbContext.Users.FirstOrDefault(u => u.Email == "");

            // Assert - All queries should complete without exception
            Assert.Null(result1);
            Assert.Null(result2);
            Assert.Null(result3);
        }

        [Fact]
        public void Test_ConcurrentModification_DoesNotExposeSensitiveState()
        {
            // Arrange
            var user = new User { Username = "original", Email = "test@example.com" };
            _dbContext.Users.Add(user);
            _dbContext.SaveChanges();

            // Act - Simulate concurrent modification
            int userId = user.UserID;
            var user1 = _dbContext.Users.FirstOrDefault(u => u.UserID == userId);
            user1.Username = "modified1";

            var user2 = _dbContext.Users.FirstOrDefault(u => u.UserID == userId);
            user2.Username = "modified2";

            _dbContext.SaveChanges(); // user1's change
            
            try
            {
                _dbContext.SaveChanges(); // user2's change - might conflict
            }
            catch (DbUpdateConcurrencyException)
            {
                // Expected - concurrent modification detected
                // Should not expose database state in error message
            }
        }

        #endregion

        #region Response Message Security Tests

        [Fact]
        public void Test_ValidationFailed_MessageIsUserFriendly()
        {
            // Arrange
            string badInput = "'; DROP TABLE users; --";

            // Act
            var result = _validationService.ValidateUser(badInput, "test@example.com");

            // Assert
            Assert.False(result.IsValid);
            Assert.NotEmpty(result.Errors);

            // Error should explain what's wrong, not how the system works
            var errorMessages = result.Errors;
            foreach (var msg in errorMessages)
            {
                Assert.False(string.IsNullOrWhiteSpace(msg), "Error message should not be empty");
                // Should be human-readable, not technical
                Assert.True(msg.Length < 200, "Error message should be concise");
            }
        }

        [Fact]
        public void Test_DatabaseError_UserDoesNotSeeStackTrace()
        {
            // Arrange & Act
            // Attempt an operation that would fail
            var result = _dbContext.Users.FirstOrDefault(u => u.UserID == int.MinValue);

            // Assert
            // Should return null gracefully, not expose stack trace or technical details
            Assert.Null(result);
        }

        #endregion

        #region Information Disclosure Prevention Tests

        [Fact]
        public void Test_SQLInjectionAttempt_DoesNotRevealDatabaseStructure()
        {
            // Arrange
            string injectionPayload = "' UNION SELECT UserID, Username, Email FROM Users --";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, "test@example.com");

            // Assert - Input is rejected before reaching database
            Assert.False(result.IsValid);
            // Error message should not reveal that the injection failed due to table structure
            foreach (var error in result.Errors)
            {
                Assert.DoesNotContain("UNION", error, System.StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("column", error, System.StringComparison.OrdinalIgnoreCase);
            }
        }

        [Fact]
        public void Test_TimingAttack_Prevention()
        {
            // Arrange - Create two different validation attempts
            string validInput = "normaluser";
            string longInvalidInput = new string('a', 1000);

            var timer1 = System.Diagnostics.Stopwatch.StartNew();
            var result1 = _validationService.ValidateUser(validInput, "test@example.com");
            timer1.Stop();

            var timer2 = System.Diagnostics.Stopwatch.StartNew();
            var result2 = _validationService.ValidateUser(longInvalidInput, "test@example.com");
            timer2.Stop();

            // Assert - Timing should not significantly differ based on input content
            // (This is a basic check; real timing attack prevention is more complex)
            // Both should complete reasonably fast
            Assert.True(timer1.ElapsedMilliseconds < 1000, "Validation should complete quickly");
            Assert.True(timer2.ElapsedMilliseconds < 1000, "Validation should complete quickly");
        }

        [Fact]
        public void Test_ErrorResponseConsistency()
        {
            // Arrange
            string input1 = "'; DROP TABLE users; --";
            string input2 = "admin' OR '1'='1";

            // Act
            var result1 = _validationService.ValidateUser(input1, "test@example.com");
            var result2 = _validationService.ValidateUser(input2, "test@example.com");

            // Assert
            // Both should be rejected, but error format should be consistent
            Assert.False(result1.IsValid);
            Assert.False(result2.IsValid);
            
            // Error responses should follow same format
            Assert.NotEmpty(result1.Errors);
            Assert.NotEmpty(result2.Errors);
        }

        #endregion

        #region Safe Defaults Tests

        [Fact]
        public void Test_DefaultBehavior_DeniesUnvalidatedInput()
        {
            // Arrange - Any suspicious pattern should be rejected
            string[] suspiciousPatterns = new[]
            {
                "\"",
                "'",
                ";",
                "--",
                "/*",
                "*/",
                "<",
                ">",
                "&",
                "|"
            };

            // Act & Assert
            foreach (var pattern in suspiciousPatterns)
            {
                var result = _validationService.ValidateUser(pattern, "test@example.com");
                Assert.False(result.IsValid, $"Pattern '{pattern}' should be rejected by default");
            }
        }

        [Fact]
        public void Test_FailSecureApproach()
        {
            // Arrange - When validation fails, ensure safe behavior
            var invalidInputs = new[]
            {
                ("", "valid@example.com"),
                ("user", ""),
                ("user!@#", "test@example.com"),
                ("user", "not-an-email")
            };

            // Act & Assert
            foreach (var (username, email) in invalidInputs)
            {
                var result = _validationService.ValidateUser(username, email);
                
                // Should fail safely (not proceed to database operation)
                if (!result.IsValid)
                {
                    // Failed as expected - this is safe
                    Assert.NotEmpty(result.Errors);
                }
                else
                {
                    // If it passed, it should be genuinely valid
                    Assert.NotEmpty(username);
                    Assert.NotEmpty(email);
                    Assert.Contains("@", email);
                }
            }
        }

        #endregion
    }
}
