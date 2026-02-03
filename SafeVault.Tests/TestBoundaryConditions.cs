using Xunit;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;
using Microsoft.EntityFrameworkCore;

namespace SafeVault.Tests
{
    /// <summary>
    /// Tests for boundary conditions and edge cases in input validation.
    /// These tests ensure the system handles extreme values, unusual inputs,
    /// and edge cases correctly without crashing or allowing bypasses.
    /// </summary>
    public class TestBoundaryConditions
    {
        private SafeVaultContext _dbContext;
        private IInputValidationService _validationService;

        public TestBoundaryConditions()
        {
            var options = new DbContextOptionsBuilder<SafeVaultContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            _dbContext = new SafeVaultContext(options);
            _dbContext.Database.EnsureCreated();
            _validationService = new InputValidationService();
        }

        #region Length Boundary Tests

        [Fact]
        public void Test_Username_AtMinimumLength_IsAccepted()
        {
            // Arrange - Username minimum is 3 characters
            string minimumUsername = "abc";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(minimumUsername, validEmail);

            // Assert
            Assert.True(result.IsValid, "Minimum length username should be accepted");
        }

        [Fact]
        public void Test_Username_BelowMinimumLength_IsRejected()
        {
            // Arrange - 2 characters, below minimum of 3
            string shortUsername = "ab";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(shortUsername, validEmail);

            // Assert
            Assert.False(result.IsValid, "Username below minimum length should be rejected");
            Assert.NotEmpty(result.Errors);
        }

        [Fact]
        public void Test_Username_AtMaximumLength_IsAccepted()
        {
            // Arrange - Maximum is 100 characters
            string maximumUsername = new string('a', 100);
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(maximumUsername, validEmail);

            // Assert
            Assert.True(result.IsValid, "Maximum length username should be accepted");
        }

        [Fact]
        public void Test_Username_ExceedsMaximumLength_IsRejected()
        {
            // Arrange - 101 characters, exceeds maximum of 100
            string tooLongUsername = new string('a', 101);
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(tooLongUsername, validEmail);

            // Assert
            Assert.False(result.IsValid, "Username exceeding maximum length should be rejected");
        }

        #endregion

        #region Empty/Null Input Tests

        [Fact]
        public void Test_EmptyUsername_IsRejected()
        {
            // Arrange
            string emptyUsername = "";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(emptyUsername, validEmail);

            // Assert
            Assert.False(result.IsValid, "Empty username should be rejected");
            Assert.NotEmpty(result.Errors);
        }

        [Fact]
        public void Test_EmptyEmail_IsRejected()
        {
            // Arrange
            string validUsername = "testuser";
            string emptyEmail = "";

            // Act
            var result = _validationService.ValidateUser(validUsername, emptyEmail);

            // Assert
            Assert.False(result.IsValid, "Empty email should be rejected");
        }

        [Fact]
        public void Test_OnlyWhitespaceUsername_IsRejected()
        {
            // Arrange
            string whitespaceUsername = "   ";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(whitespaceUsername, validEmail);

            // Assert
            Assert.False(result.IsValid, "Whitespace-only username should be rejected");
        }

        #endregion

        #region Special Character Tests

        [Fact]
        public void Test_Username_WithAllowedSpecialCharacters_IsAccepted()
        {
            // Arrange - Allowed: letters, numbers, dots, hyphens, underscores
            string usernameWithSpecial = "john_doe.smith-2024";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(usernameWithSpecial, validEmail);

            // Assert
            Assert.True(result.IsValid, "Username with allowed special characters should be accepted");
        }

        [Fact]
        public void Test_Username_WithIllegalCharacters_IsRejected()
        {
            // Arrange - Contains space, which is illegal
            string usernameWithSpace = "john doe";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(usernameWithSpace, validEmail);

            // Assert
            Assert.False(result.IsValid, "Username with spaces should be rejected");
        }

        [Fact]
        public void Test_Username_WithSymbols_IsRejected()
        {
            // Arrange - Contains $, which is illegal
            string usernameWithSymbol = "user$name";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(usernameWithSymbol, validEmail);

            // Assert
            Assert.False(result.IsValid, "Username with symbols should be rejected");
        }

        [Fact]
        public void Test_Username_WithParentheses_IsRejected()
        {
            // Arrange
            string usernameWithParens = "user(name)";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(usernameWithParens, validEmail);

            // Assert
            Assert.False(result.IsValid, "Username with parentheses should be rejected");
        }

        #endregion

        #region Numeric Tests

        [Fact]
        public void Test_NumericUsername_IsAccepted()
        {
            // Arrange - Username can be all numbers
            string numericUsername = "12345";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(numericUsername, validEmail);

            // Assert
            Assert.True(result.IsValid, "Numeric username should be accepted");
        }

        [Fact]
        public void Test_UsernameWithLeadingZeros_IsAccepted()
        {
            // Arrange
            string usernameWithZeros = "00123";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(usernameWithZeros, validEmail);

            // Assert
            Assert.True(result.IsValid, "Username with leading zeros should be accepted");
        }

        #endregion

        #region Email Boundary Tests

        [Fact]
        public void Test_Email_MinimalValid_IsAccepted()
        {
            // Arrange - Minimal valid email
            string username = "testuser";
            string minimalEmail = "a@b.co";

            // Act
            var result = _validationService.ValidateUser(username, minimalEmail);

            // Assert
            Assert.True(result.IsValid, "Minimal valid email should be accepted");
        }

        [Fact]
        public void Test_Email_WithSubdomain_IsAccepted()
        {
            // Arrange
            string username = "testuser";
            string emailWithSubdomain = "user@mail.example.com";

            // Act
            var result = _validationService.ValidateUser(username, emailWithSubdomain);

            // Assert
            Assert.True(result.IsValid, "Email with subdomain should be accepted");
        }

        [Fact]
        public void Test_Email_WithDots_IsAccepted()
        {
            // Arrange
            string username = "testuser";
            string emailWithDots = "john.doe@example.com";

            // Act
            var result = _validationService.ValidateUser(username, emailWithDots);

            // Assert
            Assert.True(result.IsValid, "Email with dots should be accepted");
        }

        [Fact]
        public void Test_Email_WithoutAtSign_IsRejected()
        {
            // Arrange
            string username = "testuser";
            string emailNoAt = "userexample.com";

            // Act
            var result = _validationService.ValidateUser(username, emailNoAt);

            // Assert
            Assert.False(result.IsValid, "Email without @ should be rejected");
        }

        [Fact]
        public void Test_Email_WithoutDomain_IsRejected()
        {
            // Arrange
            string username = "testuser";
            string emailNoDomain = "user@";

            // Act
            var result = _validationService.ValidateUser(username, emailNoDomain);

            // Assert
            Assert.False(result.IsValid, "Email without domain should be rejected");
        }

        [Fact]
        public void Test_Email_WithoutLocalPart_IsRejected()
        {
            // Arrange
            string username = "testuser";
            string emailNoLocal = "@example.com";

            // Act
            var result = _validationService.ValidateUser(username, emailNoLocal);

            // Assert
            Assert.False(result.IsValid, "Email without local part should be rejected");
        }

        #endregion

        #region Unicode and Encoding Tests

        [Fact]
        public void Test_Username_WithASCIINumbers_IsAccepted()
        {
            // Arrange
            string username = "user123";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert
            Assert.True(result.IsValid, "ASCII numbers should be accepted");
        }

        [Fact]
        public void Test_Username_WithHighASCII_IsRejected()
        {
            // Arrange - High ASCII/Unicode characters
            string username = "user\u00F1"; // ñ
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert - Validation should reject non-ASCII
            Assert.False(result.IsValid, "Non-ASCII characters should be rejected in username");
        }

        [Fact]
        public void Test_Username_WithControlCharacters_IsRejected()
        {
            // Arrange - Control character (null terminator)
            string username = "user\x00name";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert
            Assert.False(result.IsValid, "Control characters should be rejected");
        }

        #endregion

        #region Database Boundary Tests

        [Fact]
        public void Test_QueryByID_WithZeroId_ReturnsNull()
        {
            // Arrange
            var user = new User { Username = "testuser", Email = "test@example.com" };
            _dbContext.Users.Add(user);
            _dbContext.SaveChanges();

            // Act - Query for ID 0
            var result = _dbContext.Users.FirstOrDefault(u => u.UserID == 0);

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void Test_QueryByID_WithMaxInt_ReturnsNull()
        {
            // Arrange
            var user = new User { Username = "testuser", Email = "test@example.com" };
            _dbContext.Users.Add(user);
            _dbContext.SaveChanges();

            // Act - Query for max int value
            var result = _dbContext.Users.FirstOrDefault(u => u.UserID == int.MaxValue);

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void Test_InsertUser_WithMaxLengthUsername_Succeeds()
        {
            // Arrange
            var maxLengthUsername = new string('x', 100);
            var user = new User
            {
                Username = maxLengthUsername,
                Email = "test@example.com"
            };

            // Act
            _dbContext.Users.Add(user);
            _dbContext.SaveChanges();

            // Assert
            var saved = _dbContext.Users.FirstOrDefault(u => u.Username == maxLengthUsername);
            Assert.NotNull(saved);
            Assert.Equal(100, saved.Username.Length);
        }

        #endregion

        #region Mixed Valid/Invalid Pattern Tests

        [Fact]
        public void Test_Username_ValidPrefixInvalidSuffix_RejectedAsWhole()
        {
            // Arrange - Starts valid but ends with invalid characters
            string username = "valid_username!";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert
            Assert.False(result.IsValid, "Username with invalid characters should be rejected");
        }

        [Fact]
        public void Test_Email_ValidPrefixInvalidSuffix_Rejected()
        {
            // Arrange
            string username = "testuser";
            string email = "user@example.com'";

            // Act
            var result = _validationService.ValidateUser(username, email);

            // Assert
            Assert.False(result.IsValid, "Invalid email should be rejected");
        }

        #endregion
    }
}
