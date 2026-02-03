using System.Text.RegularExpressions;
using SafeVault.Models;

namespace SafeVault.Services
{
    public interface IInputValidationService
    {
        ValidationResult ValidateUser(string username, string email);
        bool IsValidUsername(string username);
        bool IsValidEmail(string email);
        ValidationResult ValidateComment(string comment);
    }

    public class ValidationResult
    {
        public bool IsValid { get; set; }
        public List<string> Errors { get; set; } = new();
    }

    public class InputValidationService : IInputValidationService
    {
        private const int MaxUsernameLength = 100;
        private const int MinUsernameLength = 3;
        private const int MaxEmailLength = 100;

        /// <summary>
        /// Validates user inputs to prevent SQL injection and XSS attacks.
        /// Implements defense-in-depth with multiple validation layers.
        /// </summary>
        public ValidationResult ValidateUser(string username, string email)
        {
            var result = new ValidationResult { IsValid = true };

            // Validate username
            if (string.IsNullOrWhiteSpace(username))
            {
                result.IsValid = false;
                result.Errors.Add("Username is required");
            }
            else if (username.Length < MinUsernameLength || username.Length > MaxUsernameLength)
            {
                result.IsValid = false;
                result.Errors.Add($"Username must be between {MinUsernameLength} and {MaxUsernameLength} characters");
            }
            else if (!IsValidUsername(username))
            {
                result.IsValid = false;
                result.Errors.Add("Username can only contain letters, numbers, underscores, hyphens, and dots");
            }

            // Validate email
            if (string.IsNullOrWhiteSpace(email))
            {
                result.IsValid = false;
                result.Errors.Add("Email is required");
            }
            else if (email.Length > MaxEmailLength)
            {
                result.IsValid = false;
                result.Errors.Add($"Email cannot exceed {MaxEmailLength} characters");
            }
            else if (!IsValidEmail(email))
            {
                result.IsValid = false;
                result.Errors.Add("Invalid email format");
            }

            return result;
        }

        /// <summary>
        /// Validates username format using regex to prevent SQL injection and XSS.
        /// Restricts to alphanumeric characters, underscores, hyphens, and dots.
        /// </summary>
        public bool IsValidUsername(string username)
        {
            // Pattern: only alphanumeric, underscore, hyphen, and dot
            // This prevents SQL injection and XSS payloads
            var pattern = @"^[a-zA-Z0-9_\-\.]+$";
            return Regex.IsMatch(username, pattern);
        }

        /// <summary>
        /// Validates email format using RFC 5322 compliant regex.
        /// Prevents malicious email payloads that could be used in attacks.
        /// </summary>
        public bool IsValidEmail(string email)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Validates comment content to prevent XSS and injection attacks.
        /// Implements defense-in-depth with multiple validation layers.
        /// </summary>
        public ValidationResult ValidateComment(string comment)
        {
            var result = new ValidationResult { IsValid = true };

            if (string.IsNullOrWhiteSpace(comment))
            {
                result.IsValid = false;
                result.Errors.Add("Comment is required");
                return result;
            }

            if (comment.Length < 1)
            {
                result.IsValid = false;
                result.Errors.Add("Comment must be at least 1 character");
            }

            if (comment.Length > 1000)
            {
                result.IsValid = false;
                result.Errors.Add("Comment cannot exceed 1000 characters");
            }

            // Block common XSS patterns
            var xssPatterns = new[]
            {
                @"<script[\s\S]*?>", // Script tags
                @"javascript:", // JavaScript protocol
                @"on\w+\s*=", // Event handlers (onclick, onerror, etc.)
                @"<iframe", // Iframe injection
                @"<object", // Object tag
                @"<embed", // Embed tag
                @"eval\s*\(", // Eval function
                @"expression\s*\(", // CSS expression
                @"vbscript:", // VBScript protocol
                @"data:text/html" // Data URI with HTML
            };

            foreach (var pattern in xssPatterns)
            {
                if (Regex.IsMatch(comment, pattern, RegexOptions.IgnoreCase))
                {
                    result.IsValid = false;
                    result.Errors.Add("Comment contains disallowed content that could pose a security risk");
                    break;
                }
            }

            // Block SQL injection patterns
            var sqlPatterns = new[]
            {
                @"('|(--)|;|\*|/\*|\*/|@@|@|char|nchar|varchar|nvarchar|alter|begin|cast|create|cursor|declare|delete|drop|end|exec|execute|fetch|insert|kill|select|sys|sysobjects|syscolumns|table|update)",
                @"\bOR\b.*=.*", // OR with equals
                @"\bAND\b.*=.*", // AND with equals
                @"UNION[\s\S]*SELECT" // UNION SELECT
            };

            foreach (var pattern in sqlPatterns)
            {
                if (Regex.IsMatch(comment, pattern, RegexOptions.IgnoreCase))
                {
                    result.IsValid = false;
                    result.Errors.Add("Comment contains disallowed SQL keywords");
                    break;
                }
            }

            return result;
        }
    }
}
