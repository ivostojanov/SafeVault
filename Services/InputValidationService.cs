using System.Text.RegularExpressions;
using SafeVault.Models;

namespace SafeVault.Services
{
    public interface IInputValidationService
    {
        ValidationResult ValidateUser(string username, string email);
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
        private bool IsValidUsername(string username)
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
        private bool IsValidEmail(string email)
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
    }
}
