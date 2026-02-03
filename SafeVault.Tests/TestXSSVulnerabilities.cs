using Xunit;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;
using Microsoft.EntityFrameworkCore;
using System.Web;

namespace SafeVault.Tests
{
    /// <summary>
    /// Comprehensive XSS (Cross-Site Scripting) vulnerability tests.
    /// Tests various XSS attack vectors to verify that the application
    /// properly defends against XSS through input validation and output encoding.
    /// </summary>
    public class TestXSSVulnerabilities
    {
        private SafeVaultContext _dbContext;
        private IInputValidationService _validationService;

        public TestXSSVulnerabilities()
        {
            var options = new DbContextOptionsBuilder<SafeVaultContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            _dbContext = new SafeVaultContext(options);
            _dbContext.Database.EnsureCreated();
            _validationService = new InputValidationService();
        }

        #region Script Tag Injection

        [Fact]
        public void Test_ScriptTag_BasicInjection()
        {
            // Arrange - Basic script tag injection
            string xssPayload = "<script>alert('xss')</script>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert - Should be rejected by input validation
            Assert.False(result.IsValid);
            Assert.NotEmpty(result.Errors);
        }

        [Fact]
        public void Test_ScriptTag_WithJavaScript()
        {
            // Arrange
            string xssPayload = "<script>document.cookie</script>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_ScriptTag_ExternalSource()
        {
            // Arrange - External script source
            string xssPayload = "<script src='http://evil.com/xss.js'></script>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_ScriptTag_DataURI()
        {
            // Arrange - Data URI with script
            string xssPayload = "<script src='data:text/javascript,alert(1)'></script>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_ScriptTag_CaseVariation()
        {
            // Arrange - Case variation to bypass filters
            string xssPayload = "<ScRiPt>alert('xss')</sCrIpT>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        #endregion

        #region Event Handler Injection

        [Fact]
        public void Test_EventHandler_OnError()
        {
            // Arrange - Image with onerror event
            string xssPayload = "<img src=x onerror=alert('xss')>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_EventHandler_OnLoad()
        {
            // Arrange
            string xssPayload = "<body onload=alert('xss')>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_EventHandler_OnMouseOver()
        {
            // Arrange
            string xssPayload = "<div onmouseover=alert('xss')>hover me</div>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_EventHandler_OnClick()
        {
            // Arrange
            string xssPayload = "<button onclick=alert('xss')>Click</button>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_EventHandler_OnFocus()
        {
            // Arrange
            string xssPayload = "<input onfocus=alert('xss') autofocus>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        #endregion

        #region HTML Tag Injection

        [Fact]
        public void Test_HTMLTag_Iframe()
        {
            // Arrange - Iframe injection
            string xssPayload = "<iframe src='javascript:alert(1)'></iframe>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_HTMLTag_Object()
        {
            // Arrange
            string xssPayload = "<object data='javascript:alert(1)'></object>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_HTMLTag_Embed()
        {
            // Arrange
            string xssPayload = "<embed src='javascript:alert(1)'>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_HTMLTag_Link()
        {
            // Arrange
            string xssPayload = "<link rel='stylesheet' href='javascript:alert(1)'>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_HTMLTag_Meta()
        {
            // Arrange
            string xssPayload = "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        #endregion

        #region SVG-Based XSS

        [Fact]
        public void Test_SVG_OnLoad()
        {
            // Arrange - SVG with onload event
            string xssPayload = "<svg onload=alert('xss')>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_SVG_AnimateTag()
        {
            // Arrange
            string xssPayload = "<svg><animate onbegin=alert('xss')>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_SVG_ScriptTag()
        {
            // Arrange
            string xssPayload = "<svg><script>alert('xss')</script></svg>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        #endregion

        #region JavaScript Protocol Handler

        [Fact]
        public void Test_JavaScriptProtocol_InHref()
        {
            // Arrange - javascript: protocol in href
            string xssPayload = "<a href='javascript:alert(1)'>click</a>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_JavaScriptProtocol_InSrc()
        {
            // Arrange
            string xssPayload = "<img src='javascript:alert(1)'>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_JavaScriptProtocol_URLEncoded()
        {
            // Arrange - Encoded javascript protocol
            string xssPayload = "<a href='jav&#97;script:alert(1)'>click</a>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        #endregion

        #region Data URI Schemes

        [Fact]
        public void Test_DataURI_TextHTML()
        {
            // Arrange - Data URI with text/html
            string xssPayload = "data:text/html,<script>alert('xss')</script>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_DataURI_Base64Encoded()
        {
            // Arrange - Base64 encoded data URI
            string xssPayload = "data:text/html;base64,PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        #endregion

        #region Attribute Injection

        [Fact]
        public void Test_AttributeInjection_BreakoutDoubleQuote()
        {
            // Arrange - Break out of double-quoted attribute
            string xssPayload = "\" onload=\"alert('xss')";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_AttributeInjection_BreakoutSingleQuote()
        {
            // Arrange - Break out of single-quoted attribute
            string xssPayload = "' onload='alert(\"xss\")";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_AttributeInjection_NoQuotes()
        {
            // Arrange - Inject without quotes
            string xssPayload = "value onclick=alert(1)";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        #endregion

        #region Encoding Bypass Attempts

        [Fact]
        public void Test_EncodingBypass_HTMLEntities()
        {
            // Arrange - HTML entity encoded script tag
            string xssPayload = "&lt;script&gt;alert('xss')&lt;/script&gt;";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_EncodingBypass_NumericEntities()
        {
            // Arrange - Numeric HTML entities
            string xssPayload = "&#60;script&#62;alert('xss')&#60;/script&#62;";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_EncodingBypass_HexEntities()
        {
            // Arrange - Hex HTML entities
            string xssPayload = "&#x3C;script&#x3E;alert('xss')&#x3C;/script&#x3E;";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_EncodingBypass_URLEncoding()
        {
            // Arrange - URL encoded
            string xssPayload = "%3Cscript%3Ealert('xss')%3C%2Fscript%3E";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_EncodingBypass_Unicode()
        {
            // Arrange - Unicode escape
            string xssPayload = "\\u003cscript\\u003ealert('xss')\\u003c/script\\u003e";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        #endregion

        #region Filter Bypass Techniques

        [Fact]
        public void Test_FilterBypass_NullByte()
        {
            // Arrange - Null byte injection
            string xssPayload = "<script\x00>alert('xss')</script>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_FilterBypass_NestedTags()
        {
            // Arrange - Nested script tags
            string xssPayload = "<scr<script>ipt>alert('xss')</scr</script>ipt>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_FilterBypass_WhitespaceVariations()
        {
            // Arrange - Extra whitespace in tags
            string xssPayload = "<  script  >alert('xss')<  /script  >";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_FilterBypass_NewlineInTag()
        {
            // Arrange - Newline characters in tag
            string xssPayload = "<script\n>alert('xss')</script>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_FilterBypass_TabInTag()
        {
            // Arrange - Tab characters in tag
            string xssPayload = "<script\t>alert('xss')</script>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        #endregion

        #region Email Field XSS

        [Fact]
        public void Test_EmailField_ScriptInjection()
        {
            // Arrange - XSS attempt in email field
            string username = "testuser";
            string xssPayload = "<script>alert('xss')</script>@example.com";

            // Act
            var result = _validationService.ValidateUser(username, xssPayload);

            // Assert - Email validation should reject this
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_EmailField_EventHandlerInjection()
        {
            // Arrange
            string username = "testuser";
            string xssPayload = "test@example.com\" onload=\"alert('xss')";

            // Act
            var result = _validationService.ValidateUser(username, xssPayload);

            // Assert
            Assert.False(result.IsValid);
        }

        #endregion

        #region Output Encoding Tests

        [Fact]
        public void Test_OutputEncoding_HTMLEncode_ScriptTag()
        {
            // Arrange - Test that output encoding works correctly
            string maliciousContent = "<script>alert('xss')</script>";

            // Act - HTML encode the output (simulating API response encoding)
            string encoded = HttpUtility.HtmlEncode(maliciousContent);

            // Assert - Dangerous characters should be encoded
            Assert.Contains("&lt;", encoded);
            Assert.Contains("&gt;", encoded);
            Assert.DoesNotContain("<script>", encoded);
        }

        [Fact]
        public void Test_OutputEncoding_HTMLEncode_SingleQuote()
        {
            // Arrange
            string maliciousContent = "'; alert('xss'); //";

            // Act
            string encoded = HttpUtility.HtmlEncode(maliciousContent);

            // Assert - Single quotes should be encoded
            Assert.Contains("&#39;", encoded);
        }

        [Fact]
        public void Test_OutputEncoding_HTMLEncode_DoubleQuote()
        {
            // Arrange
            string maliciousContent = "\"; alert('xss'); //";

            // Act
            string encoded = HttpUtility.HtmlEncode(maliciousContent);

            // Assert - Double quotes should be encoded
            Assert.Contains("&quot;", encoded);
        }

        [Fact]
        public void Test_OutputEncoding_HTMLEncode_Ampersand()
        {
            // Arrange
            string maliciousContent = "username&<script>alert(1)</script>";

            // Act
            string encoded = HttpUtility.HtmlEncode(maliciousContent);

            // Assert - Ampersand should be encoded
            Assert.Contains("&amp;", encoded);
            Assert.Contains("&lt;", encoded);
        }

        [Fact]
        public void Test_OutputEncoding_SafeData_UnaffectedByEncoding()
        {
            // Arrange - Safe, normal data
            string safeContent = "john_doe.123";

            // Act
            string encoded = HttpUtility.HtmlEncode(safeContent);

            // Assert - Safe content remains unchanged
            Assert.Equal(safeContent, encoded);
        }

        #endregion

        #region Defense in Depth Tests

        [Fact]
        public void Test_DefenseInDepth_InputValidationBlocksXSS()
        {
            // Test verifies that input validation is the first line of defense

            string[] xssPayloads = new[]
            {
                "<script>alert('xss')</script>",
                "<img src=x onerror=alert('xss')>",
                "<iframe src='javascript:alert(1)'></iframe>",
                "<svg onload=alert('xss')>",
                "javascript:alert('xss')",
                "<body onload=alert('xss')>",
                "' onload='alert(\"xss\")"
            };

            foreach (var payload in xssPayloads)
            {
                // Act
                var result = _validationService.ValidateUser(payload, "test@example.com");

                // Assert - All should be rejected at validation layer
                Assert.False(result.IsValid, $"XSS payload '{payload}' should be rejected");
            }
        }

        [Fact]
        public void Test_DefenseInDepth_ValidInputPassesThrough()
        {
            // Verify no false positives - valid input should pass validation

            string[] validUsernames = new[]
            {
                "john_doe",
                "user.name",
                "test-user",
                "user123",
                "a.b.c"
            };

            foreach (var username in validUsernames)
            {
                // Act
                var result = _validationService.ValidateUser(username, "test@example.com");

                // Assert - Valid input should pass
                Assert.True(result.IsValid, $"Valid username '{username}' should be accepted");
            }
        }

        [Fact]
        public void Test_DefenseInDepth_OutputEncodingSecondaryProtection()
        {
            // This test demonstrates that even if validation were somehow bypassed,
            // output encoding provides a second layer of protection

            // Arrange - Simulating data that needs to be displayed
            string potentiallyDangerousData = "<b>Bold</b> text";

            // Act - Encode for safe output
            string encoded = HttpUtility.HtmlEncode(potentiallyDangerousData);

            // Assert - HTML tags are escaped, preventing XSS
            Assert.Equal("&lt;b&gt;Bold&lt;/b&gt; text", encoded);
            Assert.DoesNotContain("<b>", encoded);
        }

        [Fact]
        public void Test_DefenseInDepth_MultipleEncodingLayers()
        {
            // Test that multiple encoding layers don't break functionality

            // Arrange
            string data = "user@example.com";

            // Act - Apply HTML encoding (like in API response)
            string firstPass = HttpUtility.HtmlEncode(data);
            
            // Assert - Normal data unchanged
            Assert.Equal(data, firstPass);
            
            // Act - Apply again (double encoding scenario)
            string secondPass = HttpUtility.HtmlEncode(firstPass);
            
            // Assert - Still safe, no XSS possible
            Assert.Equal(data, secondPass);
        }

        #endregion

        #region Stored XSS Prevention Tests

        [Fact]
        public void Test_StoredXSS_MaliciousDataRejectedAtInput()
        {
            // Arrange - Attempt to store XSS payload
            string xssPayload = "<script>alert('stored xss')</script>";
            string email = "test@example.com";

            // Act - Try to validate before storing
            var validationResult = _validationService.ValidateUser(xssPayload, email);

            // Assert - Should be rejected before reaching database
            Assert.False(validationResult.IsValid);
        }

        [Fact]
        public void Test_StoredXSS_DataEncodedOnRetrieval()
        {
            // Arrange - Store safe data in database
            var user = new User { Username = "testuser", Email = "test@example.com" };
            _dbContext.Users.Add(user);
            _dbContext.SaveChanges();

            // Act - Retrieve and encode for output
            var retrieved = _dbContext.Users.FirstOrDefault(u => u.Username == "testuser");
            string encodedUsername = HttpUtility.HtmlEncode(retrieved.Username);

            // Assert - Data is safely encoded for display
            Assert.NotNull(retrieved);
            Assert.Equal("testuser", encodedUsername);
        }

        #endregion

        #region Polymorphic XSS Attacks

        [Fact]
        public void Test_PolymorphicXSS_MultiContext()
        {
            // Arrange - Payload that works across different contexts
            string xssPayload = "'\"><script>alert('xss')</script>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_PolymorphicXSS_ContextBreakout()
        {
            // Arrange - Attempt to break out of multiple contexts
            string xssPayload = "</script><script>alert('xss')</script><script>";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(xssPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        #endregion
    }
}
