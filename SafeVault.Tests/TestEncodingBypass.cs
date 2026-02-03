using Xunit;
using SafeVault.Services;

namespace SafeVault.Tests
{
    /// <summary>
    /// Tests for encoding attack variations and bypass attempts.
    /// These tests verify that various encoding techniques cannot bypass
    /// the input validation security controls.
    /// </summary>
    public class TestEncodingBypass
    {
        private IInputValidationService _validationService;

        public TestEncodingBypass()
        {
            _validationService = new InputValidationService();
        }

        #region HTML Entity Encoding Tests

        [Fact]
        public void Test_HTMLEntityEncodedXSS_IsRejected()
        {
            // Arrange - HTML entity encoded script tag: &lt;script&gt;alert('xss')&lt;/script&gt;
            // Even though encoded, the regex pattern check should catch attempts
            string username = "&lt;script&gt;alert('xss')&lt;/script&gt;";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert - Entities contain angle brackets which should be rejected
            // or the full entity syntax should be rejected
            Assert.False(result.IsValid, "HTML entity encoded XSS should be rejected");
        }

        [Fact]
        public void Test_HTMLEntityWithoutSemicolon_IsRejected()
        {
            // Arrange - Malformed entity: &lt without semicolon
            string username = "user&ltscript&gt";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert - Contains characters that should be rejected
            Assert.False(result.IsValid, "Malformed HTML entity should be rejected");
        }

        #endregion

        #region Double Encoding Tests

        [Fact]
        public void Test_DoubleEncodedXSS_IsRejected()
        {
            // Arrange - URL encoded then HTML encoded: %3Cscript%3E becomes &123;
            string username = "%3Cscript%3E%3C%2Fscript%3E";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert - Percent signs should be rejected
            Assert.False(result.IsValid, "Double encoded XSS should be rejected");
        }

        [Fact]
        public void Test_URLEncodedXSS_IsRejected()
        {
            // Arrange - URL encoded script: %3C = <, %3E = >
            string username = "%3Cimg%20src=x%20onerror=alert%28%27xss%27%29%3E";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert
            Assert.False(result.IsValid, "URL encoded XSS should be rejected");
        }

        [Fact]
        public void Test_UnicodeEncodedXSS_IsRejected()
        {
            // Arrange - Unicode escape: \u003C = <
            string username = "user\\u003Cscript\\u003Ealert\\u003C/script\\u003E";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert
            Assert.False(result.IsValid, "Unicode encoded XSS should be rejected");
        }

        #endregion

        #region Null Byte Injection Tests

        [Fact]
        public void Test_NullByteInUsername_IsRejected()
        {
            // Arrange - Null byte terminator attack
            string username = "user\x00name";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert
            Assert.False(result.IsValid, "Null byte in username should be rejected");
        }

        [Fact]
        public void Test_NullByteInEmail_IsRejected()
        {
            // Arrange
            string username = "testuser";
            string email = "test@example.com\x00.attacker.com";

            // Act
            var result = _validationService.ValidateUser(username, email);

            // Assert
            Assert.False(result.IsValid, "Null byte in email should be rejected");
        }

        #endregion

        #region Case Variation Tests

        [Fact]
        public void Test_MixedCaseXSSPayload_IsRejected()
        {
            // Arrange - Case variation: <ScRiPt>
            string username = "<ScRiPt>alert('xss')</sCrIpT>";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert
            Assert.False(result.IsValid, "Mixed case XSS payload should be rejected");
        }

        [Fact]
        public void Test_MixedCaseSQLInjection_IsRejected()
        {
            // Arrange - Case variation: UnIoN SeLeCt
            string username = "admin' UnIoN SeLeCt * FROM users --";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert
            Assert.False(result.IsValid, "Mixed case SQL injection should be rejected");
        }

        #endregion

        #region Whitespace Bypass Tests

        [Fact]
        public void Test_XSSWithWhespaceVariations_IsRejected()
        {
            // Arrange - Extra spaces in tag
            string username = "<  script  >alert('xss')<  /script  >";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert
            Assert.False(result.IsValid, "XSS with whitespace should be rejected");
        }

        [Fact]
        public void Test_SQLInjectionWithNewlines_IsRejected()
        {
            // Arrange - SQL injection with newlines
            string username = "admin'\nOR\n'1'='1";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert
            Assert.False(result.IsValid, "SQL injection with newlines should be rejected");
        }

        [Fact]
        public void Test_SQLInjectionWithTabs_IsRejected()
        {
            // Arrange
            string username = "admin'\tOR\t'1'='1";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert
            Assert.False(result.IsValid, "SQL injection with tabs should be rejected");
        }

        #endregion

        #region Comment Bypass Tests

        [Fact]
        public void Test_SQLCommentWithoutDashes_IsRejected()
        {
            // Arrange - SQL comment attempt without --
            string username = "admin'/*comment*/";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert - Forward slash should be rejected
            Assert.False(result.IsValid, "SQL comment attempt should be rejected");
        }

        [Fact]
        public void Test_SQLCommentWithDashes_IsRejected()
        {
            // Arrange
            string username = "admin' -- comment";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert
            Assert.False(result.IsValid, "SQL comment with dashes should be rejected");
        }

        #endregion

        #region Nested/Layered Attack Tests

        [Fact]
        public void Test_NestedHTMLEncoding_IsRejected()
        {
            // Arrange - Multiple layers of encoding
            string username = "&lt;img&nbsp;src=x&nbsp;onerror=alert(&quot;xss&quot;)&gt;";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert
            Assert.False(result.IsValid, "Nested HTML encoding should be rejected");
        }

        [Fact]
        public void Test_EscapeSequenceBypass_IsRejected()
        {
            // Arrange - Backslash escape attempt
            string username = "user\\\\'name";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert - Quotes should be rejected
            Assert.False(result.IsValid, "Escape sequence bypass should be rejected");
        }

        #endregion

        #region Protocol Handler Tests

        [Fact]
        public void Test_JavascriptProtocolHandler_IsRejected()
        {
            // Arrange - javascript: protocol
            string username = "javascript:alert('xss')";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert - Colon should be rejected
            Assert.False(result.IsValid, "JavaScript protocol handler should be rejected");
        }

        [Fact]
        public void Test_DataProtocolHandler_IsRejected()
        {
            // Arrange
            string username = "data:text/html,<script>alert('xss')</script>";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert
            Assert.False(result.IsValid, "Data protocol handler should be rejected");
        }

        #endregion

        #region Attribute Bypass Tests

        [Fact]
        public void Test_EventHandlerWithoutQuotes_IsRejected()
        {
            // Arrange
            string username = "<div onload=alert(xss)>";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert
            Assert.False(result.IsValid, "Event handler without quotes should be rejected");
        }

        [Fact]
        public void Test_EventHandlerWithBackticks_IsRejected()
        {
            // Arrange - Backticks instead of quotes
            string username = "<div onclick=`alert('xss')`>";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert
            Assert.False(result.IsValid, "Event handler with backticks should be rejected");
        }

        #endregion

        #region Polymorphic Payload Tests

        [Fact]
        public void Test_PolymorphicXSSPayload_IsRejected()
        {
            // Arrange - Payload that works across different contexts
            string username = "'\"><script>alert('xss')</script>";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert
            Assert.False(result.IsValid, "Polymorphic XSS payload should be rejected");
        }

        [Fact]
        public void Test_PolymorphicSQLPayload_IsRejected()
        {
            // Arrange
            string username = "'; DROP TABLE users; SELECT * FROM users WHERE '1'='1";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert
            Assert.False(result.IsValid, "Polymorphic SQL payload should be rejected");
        }

        #endregion

        #region Obfuscation Tests

        [Fact]
        public void Test_ROT13EncodedPayload_IsRejected()
        {
            // Arrange - ROT13 encoded "script"
            // Note: Input validation doesn't decode ROT13, but should reject suspicious patterns
            string username = "<fpevc>alert('xss')</fpevc>";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert - Contains angle brackets which should be rejected
            Assert.False(result.IsValid, "ROT13 encoded payload should be rejected due to angle brackets");
        }

        [Fact]
        public void Test_Base64DecodablePayload_IsRejected()
        {
            // Arrange - Base64 encoded payload (even though not decoded by validator)
            string username = "PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=";
            string validEmail = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(username, validEmail);

            // Assert - Equals sign should be rejected
            Assert.False(result.IsValid, "Base64 string should be rejected due to = character");
        }

        #endregion
    }
}
