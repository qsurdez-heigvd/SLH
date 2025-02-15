//! Represents a validated email address.
//!
//! This module provides a type-safe wrapper around email addresses that ensures
//! they meet standard email format requirements. It uses the validator crate
//! to perform validation according to HTML5 email specifications.

use anyhow::{bail, Context, Result};
use std::fmt;
use validator::ValidateEmail;

/// A validated email address that is guaranteed to meet format requirements.
/// This type can only be constructed through validation, ensuring that any
/// instance is a properly formatted email address.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EmailInput {
    // The validated and normalized email address
    email: String,
}

impl EmailInput {
    /// Creates a new `EmailInput` after validating the provided email string.
    ///
    /// The email address is trimmed of whitespace and validated against HTML5
    /// email format requirements. This provides stronger guarantees than simple
    /// regex validation.
    ///
    /// # Arguments
    /// * `email` - The raw email address to validate
    ///
    /// # Returns
    /// * `Ok(EmailInput)` if the email is valid
    /// * `Err` with a descriptive message if validation fails
    ///
    /// # Example
    /// ```
    /// use your_crate::EmailInput;
    ///
    /// let email = EmailInput::new("user@example.com").unwrap();
    /// assert!(EmailInput::new("not-an-email").is_err());
    /// ```
    pub fn new(email: &str) -> Result<Self> {
        let email_trimmed = email.trim();

        // Check for empty input first
        if email_trimmed.is_empty() {
            bail!("Email address cannot be empty");
        }

        // Check maximum reasonable length
        if email_trimmed.len() > 254 {
            bail!("Email address exceeds maximum length of 254 characters");
        }

        // Validate email format
        if !email_trimmed.validate_email() {
            bail!("Invalid email format");
        }

        // Convert to lowercase for consistency
        let normalized_email = email_trimmed.to_lowercase();

        Ok(Self {
            email: normalized_email,
        })
    }

    /// Returns a string slice of the validated email address
    pub fn as_str(&self) -> &str {
        &self.email
    }
}

/// Implements Display to allow printing the email address
impl fmt::Display for EmailInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.email)
    }
}

/// Allows using EmailInput wherever a string reference is needed
impl AsRef<str> for EmailInput {
    fn as_ref(&self) -> &str {
        &self.email
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_emails() {
        let valid_emails = vec![
            "user@example.com",
            "user.name@example.com",
            "user+tag@example.com",
            "USER@EXAMPLE.COM",  // Should be normalized to lowercase
            "   user@example.com   ",  // Should be trimmed
        ];

        for email in valid_emails {
            let result = EmailInput::new(email);
            assert!(result.is_ok(), "Should accept valid email: {}", email);
        }
    }

    #[test]
    fn test_invalid_emails() {
        let binding = "a".repeat(255);
        let invalid_emails = vec![
            "",  // Empty
            " ",  // Only whitespace
            "not-an-email",
            "@example.com",
            "user@",
            "user@.",
            "user@.com",
            "user name@example.com",
            &binding,  // Too long
        ];

        for email in invalid_emails {
            let result = EmailInput::new(email);
            assert!(result.is_err(), "Should reject invalid email: {}", email);
        }
    }

    #[test]
    fn test_email_normalization() {
        let email = EmailInput::new("   USER@EXAMPLE.COM   ").unwrap();
        assert_eq!(email.as_str(), "user@example.com");
    }

    #[test]
    fn test_display_and_asref() {
        let email = EmailInput::new("user@example.com").unwrap();

        // Test Display implementation
        assert_eq!(format!("{}", email), "user@example.com");

        // Test AsRef implementation
        let reference: &str = email.as_ref();
        assert_eq!(reference, "user@example.com");
    }
}