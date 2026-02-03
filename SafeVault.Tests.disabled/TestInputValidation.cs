using NUnit.Framework;
using SafeVault.Services;

namespace SafeVault.Tests
{
    /// <summary>
    /// Tests for input validation to ensure protection against SQL injection and XSS attacks.
    /// These tests validate the InputValidationService which is the first line of defense
    /// against malicious input in the SafeVault application.
    /// </summary>
    [TestFixture]
    public class TestInputValidation
    {
        private InputValidationService _validationService;

        [SetUp]
        public void Setup()
        {
            _validationService = new InputValidationService();
        }

        #region SQL Injection Tests

        /// <summary>
        /// Test: SQL Injection with DROP TABLE payload
        /// Attack: "'; DROP TABLE users; --"
        /// Expected: Validation should fail due to illegal characters (quotes, semicolon, dashes)
        /// </summary>
        [Test]
        public void TestForSQLInjection_DropTable()
        {
            // Arrange
            string maliciousUsername = "'; DROP TABLE users; --";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(maliciousUsername, validEmail);

            // Assert
            Assert.That(result.IsValid, Is.False, "SQL injection payload should be rejected");
            Assert.That(result.Errors.Count, Is.GreaterThan(0), "Should have validation errors");
        }

        /// <summary>
        /// Test: SQL Injection with UNION SELECT payload
        /// Attack: "admin' UNION SELECT * FROM users --"
        /// Expected: Validation should fail due to spaces and special characters
        /// </summary>
        [Test]
        public void TestForSQLInjection_UnionSelect()
        {
            // Arrange
            string maliciousUsername = "admin' UNION SELECT * FROM users --";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(maliciousUsername, validEmail);

            // Assert
            Assert.That(result.IsValid, Is.False, "SQL injection UNION payload should be rejected");
        }

        /// <summary>
        /// Test: SQL Injection with OR 1=1 payload (always true condition)
        /// Attack: "' OR '1'='1"
        /// Expected: Validation should fail due to quotes and equals sign
        /// </summary>
        [Test]
        public void TestForSQLInjection_Or1Equals1()
        {
            // Arrange
            string maliciousUsername = "' OR '1'='1";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(maliciousUsername, validEmail);

            // Assert
            Assert.That(result.IsValid, Is.False, "SQL injection OR payload should be rejected");
        }

        /// <summary>
        /// Test: SQL Injection with comment sequence
        /// Attack: "admin'--"
        /// Expected: Validation should fail due to quotes and dashes
        /// </summary>
        [Test]
        public void TestForSQLInjection_CommentSequence()
        {
            // Arrange
            string maliciousUsername = "admin'--";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(maliciousUsername, validEmail);

            // Assert
            Assert.That(result.IsValid, Is.False, "Comment sequence should be rejected");
        }

        /// <summary>
        /// Test: SQL Injection with stacked queries
        /// Attack: "admin'; SELECT * FROM users; --"
        /// Expected: Validation should fail due to quotes, semicolons, and spaces
        /// </summary>
        [Test]
        public void TestForSQLInjection_StackedQueries()
        {
            // Arrange
            string maliciousUsername = "admin'; SELECT * FROM users; --";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(maliciousUsername, validEmail);

            // Assert
            Assert.That(result.IsValid, Is.False, "Stacked queries should be rejected");
        }

        #endregion

        #region XSS (Cross-Site Scripting) Tests

        /// <summary>
        /// Test: XSS with script tag
        /// Attack: "<script>alert('xss')</script>"
        /// Expected: Validation should fail due to angle brackets and special characters
        /// </summary>
        [Test]
        public void TestForXSS_ScriptTag()
        {
            // Arrange
            string xssUsername = "<script>alert('xss')</script>";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssUsername, validEmail);

            // Assert
            Assert.That(result.IsValid, Is.False, "Script tag should be rejected");
        }

        /// <summary>
        /// Test: XSS with img tag and onerror event
        /// Attack: "<img src=x onerror=alert('xss')>"
        /// Expected: Validation should fail due to angle brackets
        /// </summary>
        [Test]
        public void TestForXSS_ImgOnerror()
        {
            // Arrange
            string xssUsername = "<img src=x onerror=alert('xss')>";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssUsername, validEmail);

            // Assert
            Assert.That(result.IsValid, Is.False, "Image onerror payload should be rejected");
        }

        /// <summary>
        /// Test: XSS with iframe tag
        /// Attack: "<iframe src='javascript:alert(\"xss\")'></iframe>"
        /// Expected: Validation should fail due to angle brackets
        /// </summary>
        [Test]
        public void TestForXSS_IframeTag()
        {
            // Arrange
            string xssUsername = "<iframe src='javascript:alert(\"xss\")'></iframe>";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssUsername, validEmail);

            // Assert
            Assert.That(result.IsValid, Is.False, "Iframe tag should be rejected");
        }

        /// <summary>
        /// Test: XSS with event handler in div
        /// Attack: "<div onmouseover=alert('xss')>hover me</div>"
        /// Expected: Validation should fail due to angle brackets
        /// </summary>
        [Test]
        public void TestForXSS_DivOnmouseover()
        {
            // Arrange
            string xssUsername = "<div onmouseover=alert('xss')>hover me</div>";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssUsername, validEmail);

            // Assert
            Assert.That(result.IsValid, Is.False, "Div with event handler should be rejected");
        }

        /// <summary>
        /// Test: XSS with SVG payload
        /// Attack: "<svg onload=alert('xss')>"
        /// Expected: Validation should fail due to angle brackets
        /// </summary>
        [Test]
        public void TestForXSS_SvgOnload()
        {
            // Arrange
            string xssUsername = "<svg onload=alert('xss')>";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssUsername, validEmail);

            // Assert
            Assert.That(result.IsValid, Is.False, "SVG onload payload should be rejected");
        }

        #endregion

        #region Valid Input Tests

        /// <summary>
        /// Test: Valid username and email
        /// Expected: Validation should succeed
        /// </summary>
        [Test]
        public void TestValidInput_StandardUserAndEmail()
        {
            // Arrange
            string validUsername = "john_doe";
            string validEmail = "john.doe@example.com";

            // Act
            var result = _validationService.ValidateUser(validUsername, validEmail);

            // Assert
            Assert.That(result.IsValid, Is.True, "Valid input should pass validation");
            Assert.That(result.Errors.Count, Is.EqualTo(0), "Should have no validation errors");
        }

        /// <summary>
        /// Test: Valid username with allowed special characters (dots, hyphens, underscores)
        /// Expected: Validation should succeed
        /// </summary>
        [Test]
        public void TestValidInput_UsernameWithAllowedSpecialChars()
        {
            // Arrange
            string validUsername = "user.name-123_test";
            string validEmail = "user@example.com";

            // Act
            var result = _validationService.ValidateUser(validUsername, validEmail);

            // Assert
            Assert.That(result.IsValid, Is.True, "Username with allowed special characters should pass");
        }

        /// <summary>
        /// Test: Valid username at maximum length (100 characters)
        /// Expected: Validation should succeed
        /// </summary>
        [Test]
        public void TestValidInput_MaxLengthUsername()
        {
            // Arrange
            string validUsername = new string('a', 100);
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(validUsername, validEmail);

            // Assert
            Assert.That(result.IsValid, Is.True, "Username at max length should pass");
        }

        /// <summary>
        /// Test: Valid numeric username
        /// Expected: Validation should succeed
        /// </summary>
        [Test]
        public void TestValidInput_NumericUsername()
        {
            // Arrange
            string validUsername = "12345678";
            string validEmail = "numeric@example.com";

            // Act
            var result = _validationService.ValidateUser(validUsername, validEmail);

            // Assert
            Assert.That(result.IsValid, Is.True, "Numeric username should pass");
        }

        #endregion

        #region Email Validation Tests

        /// <summary>
        /// Test: Invalid email in form (missing @)
        /// Expected: Validation should fail
        /// </summary>
        [Test]
        public void TestEmailValidation_MissingAtSymbol()
        {
            // Arrange
            string validUsername = "testuser";
            string invalidEmail = "testuser.example.com";

            // Act
            var result = _validationService.ValidateUser(validUsername, invalidEmail);

            // Assert
            Assert.That(result.IsValid, Is.False, "Email without @ should be rejected");
        }

        /// <summary>
        /// Test: Invalid email with SQL injection in email field
        /// Attack: "test@example.com'; DROP TABLE users; --"
        /// Expected: Validation should fail due to illegal characters in email
        /// </summary>
        [Test]
        public void TestEmailValidation_SQLInjectionInEmail()
        {
            // Arrange
            string validUsername = "testuser";
            string injectedEmail = "test@example.com'; DROP TABLE users; --";

            // Act
            var result = _validationService.ValidateUser(validUsername, injectedEmail);

            // Assert
            Assert.That(result.IsValid, Is.False, "Email with SQL injection should be rejected");
        }

        #endregion

        #region Length and Required Field Tests

        /// <summary>
        /// Test: Empty username
        /// Expected: Validation should fail
        /// </summary>
        [Test]
        public void TestLengthValidation_EmptyUsername()
        {
            // Arrange
            string emptyUsername = "";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(emptyUsername, validEmail);

            // Assert
            Assert.That(result.IsValid, Is.False, "Empty username should be rejected");
        }

        /// <summary>
        /// Test: Username below minimum length
        /// Expected: Validation should fail
        /// </summary>
        [Test]
        public void TestLengthValidation_BelowMinLength()
        {
            // Arrange
            string shortUsername = "ab";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(shortUsername, validEmail);

            // Assert
            Assert.That(result.IsValid, Is.False, "Username below min length should be rejected");
        }

        /// <summary>
        /// Test: Username exceeding maximum length
        /// Expected: Validation should fail
        /// </summary>
        [Test]
        public void TestLengthValidation_ExceedsMaxLength()
        {
            // Arrange
            string longUsername = new string('a', 101);
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(longUsername, validEmail);

            // Assert
            Assert.That(result.IsValid, Is.False, "Username exceeding max length should be rejected");
        }

        /// <summary>
        /// Test: Empty email
        /// Expected: Validation should fail
        /// </summary>
        [Test]
        public void TestLengthValidation_EmptyEmail()
        {
            // Arrange
            string validUsername = "testuser";
            string emptyEmail = "";

            // Act
            var result = _validationService.ValidateUser(validUsername, emptyEmail);

            // Assert
            Assert.That(result.IsValid, Is.False, "Empty email should be rejected");
        }

        #endregion
    }
}
