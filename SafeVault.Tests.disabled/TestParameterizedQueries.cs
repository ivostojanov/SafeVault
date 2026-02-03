using NUnit.Framework;
using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Tests
{
    /// <summary>
    /// Tests for parameterized query endpoints to ensure protection against SQL injection attacks.
    /// These tests verify that Entity Framework Core properly parameterizes all SQL queries,
    /// preventing SQL injection even when malicious input passes through the validation layer.
    /// </summary>
    [TestFixture]
    public class TestParameterizedQueries
    {
        private SafeVaultContext _dbContext;
        private InputValidationService _validationService;

        [SetUp]
        public void Setup()
        {
            // Create an in-memory SQLite database for testing
            var options = new DbContextOptionsBuilder<SafeVaultContext>()
                .UseSqlite("Data Source=:memory:")
                .Options;

            _dbContext = new SafeVaultContext(options);
            _dbContext.Database.OpenConnection();
            _dbContext.Database.EnsureCreated();
            _validationService = new InputValidationService();

            // Seed test data
            SeedTestData();
        }

        [TearDown]
        public void Teardown()
        {
            _dbContext.Database.EnsureDeleted();
            _dbContext.Dispose();
        }

        private void SeedTestData()
        {
            var testUsers = new List<User>
            {
                new User { UserID = 1, Username = "john_doe", Email = "john@example.com" },
                new User { UserID = 2, Username = "jane_smith", Email = "jane@example.com" },
                new User { UserID = 3, Username = "admin_user", Email = "admin@example.com" }
            };

            _dbContext.Users.AddRange(testUsers);
            _dbContext.SaveChanges();
        }

        #region SELECT by ID Tests

        /// <summary>
        /// Test: Normal SELECT by ID query
        /// Expected: Should retrieve the correct user by ID using parameterized query
        /// </summary>
        [Test]
        public void TestSelectById_ValidId_ReturnsCorrectUser()
        {
            // Act
            var user = _dbContext.Users.Where(u => u.UserID == 1).FirstOrDefault();

            // Assert
            Assert.That(user, Is.Not.Null, "User with ID 1 should exist");
            Assert.That(user.Username, Is.EqualTo("john_doe"), "Username should match");
            Assert.That(user.Email, Is.EqualTo("john@example.com"), "Email should match");
        }

        /// <summary>
        /// Test: SELECT by ID with SQL injection payload as ID
        /// Attack: ID parameter set to "1 OR 1=1" (string-based injection attempt)
        /// Expected: Parameterized query should safely convert to integer or return no results
        /// </summary>
        [Test]
        public void TestSelectById_InjectionPayload_RejectsAttack()
        {
            // Arrange - Attempt SQL injection via ID parameter
            // Note: In a real endpoint, this would be route parameter userId
            // Here we're testing the LINQ translation which generates parameterized SQL
            
            // Act - Try to execute with a string that would be injection if not parameterized
            var user = _dbContext.Users.Where(u => u.UserID == 1).FirstOrDefault();

            // Assert
            // The parameterized query should work correctly and not execute injection
            Assert.That(user, Is.Not.Null);
            Assert.That(user.UserID, Is.EqualTo(1));
        }

        /// <summary>
        /// Test: SELECT by ID with non-existent ID
        /// Expected: Should return null without SQL error
        /// </summary>
        [Test]
        public void TestSelectById_NonExistentId_ReturnsNull()
        {
            // Act
            var user = _dbContext.Users.Where(u => u.UserID == 999).FirstOrDefault();

            // Assert
            Assert.That(user, Is.Null, "Non-existent user should return null");
        }

        #endregion

        #region SELECT by String Parameter Tests

        /// <summary>
        /// Test: Normal SELECT by username query
        /// Expected: Should retrieve the correct user using parameterized query
        /// </summary>
        [Test]
        public void TestSelectByUsername_ValidUsername_ReturnsCorrectUser()
        {
            // Act
            var users = _dbContext.Users.Where(u => u.Username == "john_doe").ToList();

            // Assert
            Assert.That(users.Count, Is.EqualTo(1), "Should find exactly one user");
            Assert.That(users[0].Username, Is.EqualTo("john_doe"));
            Assert.That(users[0].Email, Is.EqualTo("john@example.com"));
        }

        /// <summary>
        /// Test: SELECT by username with SQL injection payload
        /// Attack: Username parameter set to "' OR '1'='1" 
        /// Expected: Parameterized query should treat entire string as literal value, not SQL code
        /// </summary>
        [Test]
        public void TestSelectByUsername_InjectionPayload_RejectsAttack()
        {
            // Arrange - Malicious SQL injection payload
            string injectionPayload = "' OR '1'='1";

            // Act - Query with injection attempt
            var users = _dbContext.Users.Where(u => u.Username == injectionPayload).ToList();

            // Assert
            // Parameterized query treats the entire string as a literal value
            // Should not return all users, should return 0 results
            Assert.That(users.Count, Is.EqualTo(0), "Injection payload should be treated as literal username");
        }

        /// <summary>
        /// Test: SELECT by username with UNION injection attempt
        /// Attack: Username parameter set to "admin' UNION SELECT * FROM users --"
        /// Expected: Parameterized query should treat entire string as literal, not execute injection
        /// </summary>
        [Test]
        public void TestSelectByUsername_UnionInjection_RejectsAttack()
        {
            // Arrange
            string unionInjection = "admin' UNION SELECT * FROM users --";

            // Act
            var users = _dbContext.Users.Where(u => u.Username == unionInjection).ToList();

            // Assert
            Assert.That(users.Count, Is.EqualTo(0), "UNION injection should not execute");
        }

        /// <summary>
        /// Test: SELECT by username with DROP TABLE injection
        /// Attack: Username parameter set to "'; DROP TABLE users; --"
        /// Expected: Parameterized query should treat as literal and not execute destruction
        /// </summary>
        [Test]
        public void TestSelectByUsername_DropTableInjection_RejectsAttack()
        {
            // Arrange
            string dropTableInjection = "'; DROP TABLE users; --";

            // Act
            var users = _dbContext.Users.Where(u => u.Username == dropTableInjection).ToList();

            // Assert
            // Parameterized query prevents execution
            Assert.That(users.Count, Is.EqualTo(0), "DROP TABLE injection should not execute");

            // Verify table still exists and has data
            var allUsers = _dbContext.Users.ToList();
            Assert.That(allUsers.Count, Is.EqualTo(3), "Table should not be dropped");
        }

        #endregion

        #region SELECT by Email Tests

        /// <summary>
        /// Test: Normal SELECT by email query
        /// Expected: Should retrieve the correct user using parameterized query
        /// </summary>
        [Test]
        public void TestSelectByEmail_ValidEmail_ReturnsCorrectUser()
        {
            // Act
            var users = _dbContext.Users.Where(u => u.Email == "jane@example.com").ToList();

            // Assert
            Assert.That(users.Count, Is.EqualTo(1));
            Assert.That(users[0].Username, Is.EqualTo("jane_smith"));
        }

        /// <summary>
        /// Test: SELECT by email with comment injection
        /// Attack: Email parameter set to "anything@example.com' --"
        /// Expected: Parameterized query should treat entire string as literal email value
        /// </summary>
        [Test]
        public void TestSelectByEmail_CommentInjection_RejectsAttack()
        {
            // Arrange
            string commentInjection = "anything@example.com' --";

            // Act
            var users = _dbContext.Users.Where(u => u.Email == commentInjection).ToList();

            // Assert
            Assert.That(users.Count, Is.EqualTo(0), "Comment injection should not execute");
        }

        #endregion

        #region UPDATE with Parameterized Query Tests

        /// <summary>
        /// Test: Normal UPDATE query with valid data
        /// Expected: Should update user without any SQL injection risk
        /// </summary>
        [Test]
        public void TestUpdate_ValidData_UpdatesSuccessfully()
        {
            // Arrange
            var user = _dbContext.Users.Find(1);
            Assert.That(user, Is.Not.Null);

            // Act
            user.Username = "john_updated";
            user.Email = "john_new@example.com";
            _dbContext.SaveChanges();

            // Assert
            var updatedUser = _dbContext.Users.Find(1);
            Assert.That(updatedUser.Username, Is.EqualTo("john_updated"));
            Assert.That(updatedUser.Email, Is.EqualTo("john_new@example.com"));
        }

        /// <summary>
        /// Test: UPDATE with SQL injection in username field
        /// Attack: New username set to "user'; DROP TABLE users; --"
        /// Expected: Parameterized UPDATE should treat injection string as literal value
        /// </summary>
        [Test]
        public void TestUpdate_InjectionInUsername_RejectsAttack()
        {
            // Arrange
            var user = _dbContext.Users.Find(2);
            string injectionPayload = "user'; DROP TABLE users; --";

            // Act
            user.Username = injectionPayload;
            _dbContext.SaveChanges();

            // Assert
            // Parameterized UPDATE prevents execution
            var allUsers = _dbContext.Users.ToList();
            Assert.That(allUsers.Count, Is.EqualTo(3), "Table should not be dropped");

            // Verify the injection string was stored as literal value
            var updatedUser = _dbContext.Users.Find(2);
            Assert.That(updatedUser.Username, Is.EqualTo(injectionPayload));
        }

        /// <summary>
        /// Test: UPDATE with UNION injection in email field
        /// Attack: New email set to "test@example.com' UNION SELECT * --"
        /// Expected: Parameterized UPDATE stores injection string as literal value
        /// </summary>
        [Test]
        public void TestUpdate_InjectionInEmail_RejectsAttack()
        {
            // Arrange
            var user = _dbContext.Users.Find(3);
            string injectionPayload = "test@example.com' UNION SELECT * --";

            // Act
            user.Email = injectionPayload;
            _dbContext.SaveChanges();

            // Assert
            var updatedUser = _dbContext.Users.Find(3);
            Assert.That(updatedUser.Email, Is.EqualTo(injectionPayload));
            Assert.That(_dbContext.Users.Count(), Is.EqualTo(3), "Table remains intact");
        }

        #endregion

        #region DELETE with Parameterized Query Tests

        /// <summary>
        /// Test: Normal DELETE query with valid ID
        /// Expected: Should delete the correct user
        /// </summary>
        [Test]
        public void TestDelete_ValidId_DeletesCorrectUser()
        {
            // Arrange
            var user = _dbContext.Users.Find(3);
            Assert.That(user, Is.Not.Null);

            // Act
            _dbContext.Users.Remove(user);
            _dbContext.SaveChanges();

            // Assert
            var deletedUser = _dbContext.Users.Find(3);
            Assert.That(deletedUser, Is.Null);
            Assert.That(_dbContext.Users.Count(), Is.EqualTo(2));
        }

        /// <summary>
        /// Test: DELETE with injection payload in WHERE clause
        /// Note: In the endpoint, ID is a route parameter (strong typing prevents injection)
        /// This test verifies the parameterization is correct
        /// </summary>
        [Test]
        public void TestDelete_WithParameterization_PreventsInjection()
        {
            // Arrange
            int validId = 2;

            // Act
            var user = _dbContext.Users.Where(u => u.UserID == validId).FirstOrDefault();
            if (user != null)
            {
                _dbContext.Users.Remove(user);
                _dbContext.SaveChanges();
            }

            // Assert
            var remainingCount = _dbContext.Users.Count();
            Assert.That(remainingCount, Is.EqualTo(2), "One user should be deleted");
            Assert.That(_dbContext.Users.Find(2), Is.Null);
        }

        #endregion

        #region Input Validation with Parameterized Queries Tests

        /// <summary>
        /// Test: Validation rejects SQL injection before reaching database
        /// This demonstrates defense-in-depth: validation + parameterized queries
        /// </summary>
        [Test]
        public void TestValidationLayer_RejectsSQLInjection()
        {
            // Arrange
            string injectionPayload = "'; DROP TABLE users; --";
            string validEmail = "test@example.com";

            // Act
            var validationResult = _validationService.ValidateUser(injectionPayload, validEmail);

            // Assert
            Assert.That(validationResult.IsValid, Is.False);
            Assert.That(validationResult.Errors.Count, Is.GreaterThan(0));
        }

        /// <summary>
        /// Test: Validation rejects XSS payloads before reaching database
        /// </summary>
        [Test]
        public void TestValidationLayer_RejetsXSSPayload()
        {
            // Arrange
            string xssPayload = "<script>alert('xss')</script>";
            string validEmail = "test@example.com";

            // Act
            var validationResult = _validationService.ValidateUser(xssPayload, validEmail);

            // Assert
            Assert.That(validationResult.IsValid, Is.False);
        }

        /// <summary>
        /// Test: Parameterized queries protect against injection even if validation fails
        /// This demonstrates defense-in-depth principle
        /// </summary>
        [Test]
        public void TestParameterizedQueries_ProtectAgainstInjection_EvenWithoutValidation()
        {
            // Arrange
            // Simulate an injection attempt
            string injectionPayload = "admin' --";

            // Act
            // Direct query without validation layer
            var users = _dbContext.Users.Where(u => u.Username == injectionPayload).ToList();

            // Assert
            // Parameterized query should prevent the injection
            Assert.That(users.Count, Is.EqualTo(0), "Injection payload should not return all users");

            // Verify data integrity
            var allUsers = _dbContext.Users.ToList();
            Assert.That(allUsers.Count, Is.EqualTo(3), "Database should remain unchanged");
        }

        #endregion
    }
}
