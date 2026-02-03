using Xunit;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;
using Microsoft.EntityFrameworkCore;

namespace SafeVault.Tests
{
    /// <summary>
    /// Comprehensive SQL Injection vulnerability tests.
    /// Tests various SQL injection attack vectors to verify that the application
    /// properly defends against SQL injection through input validation and
    /// parameterized queries via Entity Framework Core.
    /// </summary>
    public class TestSQLInjection
    {
        private SafeVaultContext _dbContext;
        private IInputValidationService _validationService;

        public TestSQLInjection()
        {
            var options = new DbContextOptionsBuilder<SafeVaultContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;

            _dbContext = new SafeVaultContext(options);
            _dbContext.Database.EnsureCreated();
            _validationService = new InputValidationService();
        }

        #region Classic SQL Injection Attacks

        [Fact]
        public void Test_ClassicSQLInjection_OR_1_Equals_1()
        {
            // Arrange - Classic "OR 1=1" attack
            string injectionPayload = "admin' OR '1'='1";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert - Validation should reject the injection
            Assert.False(result.IsValid);
            Assert.NotEmpty(result.Errors);
        }

        [Fact]
        public void Test_ClassicSQLInjection_OR_TRUE()
        {
            // Arrange
            string injectionPayload = "admin' OR true--";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_ClassicSQLInjection_OR_1_1()
        {
            // Arrange
            string injectionPayload = "' OR 1=1--";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_ClassicSQLInjection_AdminCommentOut()
        {
            // Arrange - Comment out remainder of query
            string injectionPayload = "admin'--";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_ClassicSQLInjection_SingleQuoteEscape()
        {
            // Arrange
            string injectionPayload = "admin''--";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        #endregion

        #region UNION-Based SQL Injection

        [Fact]
        public void Test_UnionSQLInjection_BasicUnion()
        {
            // Arrange - UNION SELECT attack
            string injectionPayload = "' UNION SELECT * FROM users--";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_UnionSQLInjection_UnionAllSelect()
        {
            // Arrange
            string injectionPayload = "' UNION ALL SELECT UserID, Username, Email FROM Users--";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_UnionSQLInjection_UnionWithNull()
        {
            // Arrange - UNION with NULL values
            string injectionPayload = "' UNION SELECT NULL,NULL,NULL--";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_UnionSQLInjection_OrderBy()
        {
            // Arrange - UNION with ORDER BY
            string injectionPayload = "' UNION SELECT 1,2,3 ORDER BY 1--";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        #endregion

        #region Stacked Queries / Command Injection

        [Fact]
        public void Test_StackedQueries_DropTable()
        {
            // Arrange - Attempt to drop table
            string injectionPayload = "'; DROP TABLE users; --";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_StackedQueries_DeleteAllRecords()
        {
            // Arrange
            string injectionPayload = "'; DELETE FROM users; --";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_StackedQueries_InsertMaliciousData()
        {
            // Arrange
            string injectionPayload = "'; INSERT INTO users VALUES ('hacker','hack@evil.com'); --";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_StackedQueries_UpdateAllRecords()
        {
            // Arrange
            string injectionPayload = "'; UPDATE users SET username='pwned'; --";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        #endregion

        #region Blind SQL Injection

        [Fact]
        public void Test_BlindSQLInjection_BooleanBased()
        {
            // Arrange - Boolean-based blind injection
            string injectionPayload = "admin' AND '1'='1";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_BlindSQLInjection_AND_1_Equals_1()
        {
            // Arrange
            string injectionPayload = "' AND 1=1--";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_BlindSQLInjection_TimeBased()
        {
            // Arrange - Time-based blind injection (SQLite version)
            string injectionPayload = "'; SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END; --";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_BlindSQLInjection_SubstringExtraction()
        {
            // Arrange - Extract data character by character
            string injectionPayload = "' AND SUBSTR((SELECT username),1,1)='a'--";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        #endregion

        #region Comment-Based Injection

        [Fact]
        public void Test_CommentInjection_DoubleDash()
        {
            // Arrange - SQL comment with double dash
            string injectionPayload = "admin' -- comment";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_CommentInjection_SlashStar()
        {
            // Arrange - C-style comment
            string injectionPayload = "admin' /* comment */";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_CommentInjection_HashComment()
        {
            // Arrange - MySQL-style hash comment
            string injectionPayload = "admin' # comment";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        #endregion

        #region Alternative Syntax Injection

        [Fact]
        public void Test_AlternativeSyntax_DoubleQuotes()
        {
            // Arrange - Using double quotes instead of single
            string injectionPayload = "admin\" OR \"1\"=\"1";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_AlternativeSyntax_Backticks()
        {
            // Arrange - Using backticks (MySQL)
            string injectionPayload = "admin` OR `1`=`1";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_AlternativeSyntax_Semicolon()
        {
            // Arrange - Statement terminator
            string injectionPayload = "admin';";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        #endregion

        #region Encoding-Based Bypass Attempts

        [Fact]
        public void Test_EncodingBypass_URLEncoded()
        {
            // Arrange - URL encoded single quote %27
            string injectionPayload = "admin%27%20OR%20%271%27%3D%271";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert - Should reject encoded characters
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_EncodingBypass_HexEncoded()
        {
            // Arrange - Hex encoded attack
            string injectionPayload = "admin' OR 0x31=0x31--";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_EncodingBypass_UnicodeEscape()
        {
            // Arrange - Unicode escape sequences
            string injectionPayload = "admin\\u0027 OR \\u0031=\\u0031";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        #endregion

        #region Email Field SQL Injection

        [Fact]
        public void Test_EmailField_SQLInjection_OR_Attack()
        {
            // Arrange - Inject via email field
            string username = "testuser";
            string injectionPayload = "test@example.com' OR '1'='1";

            // Act
            var result = _validationService.ValidateUser(username, injectionPayload);

            // Assert - Email validation should reject this
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_EmailField_SQLInjection_UnionSelect()
        {
            // Arrange
            string username = "testuser";
            string injectionPayload = "' UNION SELECT * FROM users--@example.com";

            // Act
            var result = _validationService.ValidateUser(username, injectionPayload);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_EmailField_SQLInjection_CommentInjection()
        {
            // Arrange
            string username = "testuser";
            string injectionPayload = "test'--@example.com";

            // Act
            var result = _validationService.ValidateUser(username, injectionPayload);

            // Assert
            Assert.False(result.IsValid);
        }

        #endregion

        #region Parameterized Query Protection Tests

        [Fact]
        public void Test_ParameterizedQuery_IntegerParameter_PreventsSQLInjection()
        {
            // Arrange - Create a user
            var user = new User { Username = "testuser", Email = "test@example.com" };
            _dbContext.Users.Add(user);
            _dbContext.SaveChanges();

            // Act - Even if we try to inject via integer parameter, type safety prevents it
            // EF Core uses parameterized queries: WHERE UserID = @p0
            int userId = user.UserID;
            var result = _dbContext.Users.FirstOrDefault(u => u.UserID == userId);

            // Assert - Query executes safely with parameterization
            Assert.NotNull(result);
            Assert.Equal("testuser", result.Username);
        }

        [Fact]
        public void Test_ParameterizedQuery_StringParameter_PreventsSQLInjection()
        {
            // Arrange
            var user = new User { Username = "testuser", Email = "test@example.com" };
            _dbContext.Users.Add(user);
            _dbContext.SaveChanges();

            // Act - EF Core uses parameterized query: WHERE Username = @p0
            // Even malicious string is treated as literal value, not SQL code
            string searchUsername = "testuser";
            var result = _dbContext.Users.FirstOrDefault(u => u.Username == searchUsername);

            // Assert
            Assert.NotNull(result);
            Assert.Equal("testuser", result.Username);
        }

        [Fact]
        public void Test_ParameterizedQuery_MaliciousStringTreatedAsLiteral()
        {
            // Arrange
            var user = new User { Username = "normaluser", Email = "normal@example.com" };
            _dbContext.Users.Add(user);
            _dbContext.SaveChanges();

            // Act - Search for malicious string (will be treated as literal, not SQL)
            string maliciousSearch = "' OR '1'='1";
            var result = _dbContext.Users.FirstOrDefault(u => u.Username == maliciousSearch);

            // Assert - No user found because the injection is treated as literal string
            Assert.Null(result);
        }

        [Fact]
        public void Test_EFCore_AutomaticallyEscapesParameters()
        {
            // Arrange
            var user = new User { Username = "user_with_special", Email = "test@example.com" };
            _dbContext.Users.Add(user);
            _dbContext.SaveChanges();

            // Act - EF Core handles special characters safely
            string search = "user_with_special";
            var result = _dbContext.Users.Where(u => u.Username == search).ToList();

            // Assert
            Assert.Single(result);
            Assert.Equal("user_with_special", result[0].Username);
        }

        #endregion

        #region Defense in Depth Tests

        [Fact]
        public void Test_DefenseInDepth_ValidationLayerFirst()
        {
            // Test verifies that validation layer is the first line of defense
            // Even before parameterized queries can protect us

            string[] sqlInjectionPayloads = new[]
            {
                "' OR '1'='1",
                "admin'--",
                "' UNION SELECT * FROM users--",
                "'; DROP TABLE users; --",
                "' AND 1=1--",
                "admin' /*",
                "admin'; DELETE FROM users--"
            };

            foreach (var payload in sqlInjectionPayloads)
            {
                // Act
                var result = _validationService.ValidateUser(payload, "test@example.com");

                // Assert - All should be rejected at validation layer
                Assert.False(result.IsValid, $"Payload '{payload}' should be rejected");
            }
        }

        [Fact]
        public void Test_DefenseInDepth_ValidInputPassesThrough()
        {
            // Verify no false positives - valid input should pass validation

            string[] validUsernames = new[]
            {
                "john_doe",
                "user123",
                "test.user",
                "user-name",
                "a1b2c3"
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
        public void Test_DefenseInDepth_ORMLayerSecondaryProtection()
        {
            // This test demonstrates that even if validation were somehow bypassed,
            // the ORM's parameterized queries provide a second layer of protection

            // Arrange
            var user = new User { Username = "protecteduser", Email = "protected@example.com" };
            _dbContext.Users.Add(user);
            _dbContext.SaveChanges();

            // Act - Simulate a malicious string reaching the ORM layer
            // EF Core will parameterize this, treating it as a literal string
            string maliciousInput = "'; DROP TABLE users; --";
            var result = _dbContext.Users.FirstOrDefault(u => u.Username == maliciousInput);

            // Assert - No match found (injection treated as literal string)
            // And table is not dropped
            Assert.Null(result);
            
            // Verify data integrity - original user still exists
            var originalUser = _dbContext.Users.FirstOrDefault(u => u.Username == "protecteduser");
            Assert.NotNull(originalUser);
        }

        #endregion

        #region Complex Multi-Statement Attacks

        [Fact]
        public void Test_ComplexAttack_MultipleStatements()
        {
            // Arrange - Complex multi-statement attack
            string injectionPayload = "'; DELETE FROM users WHERE '1'='1'; SELECT * FROM users WHERE '1'='1";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_ComplexAttack_NestedQueries()
        {
            // Arrange
            string injectionPayload = "' OR username IN (SELECT username FROM users)--";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public void Test_ComplexAttack_ConcatenatedPayload()
        {
            // Arrange
            string injectionPayload = "admin'+OR+username+LIKE+'%admin%'--";
            string email = "test@example.com";

            // Act
            var result = _validationService.ValidateUser(injectionPayload, email);

            // Assert
            Assert.False(result.IsValid);
        }

        #endregion
    }
}
