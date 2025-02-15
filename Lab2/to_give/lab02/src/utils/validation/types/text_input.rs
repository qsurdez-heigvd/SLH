//! Provides a secure and validated text content representation.
//!
//! This module ensures that text content meets safety requirements by:
//! - Validating length constraints
//! - Checking for control characters that could be dangerous
//! - Preventing HTML injection
//! - Normalizing whitespace

use ammonia::is_html;
use anyhow::{bail, Context, Result};
use std::fmt;
use unicode_normalization::UnicodeNormalization;
use validator::ValidateNonControlCharacter;

use crate::utils::validation::{MAX_CONTENT_LENGTH, MAX_SHORT_CONTENT_LENGTH};

/// Represents validated textual content that is guaranteed to be safe for use.
/// This type can only be constructed through validation, ensuring that any
/// instance meets our security and formatting requirements.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TextInput {
    // The validated and normalized text content
    text_content: String,
}

impl TextInput {
    /// Creates a new TextContent instance for long-form content like blog posts
    /// or articles. This applies the maximum length constraint for long content.
    ///
    /// # Arguments
    /// * `content` - The text content to validate
    ///
    /// # Example
    /// ```
    /// use your_crate::TextContent;
    ///
    /// let article = TextContent::new_long_form("This is a long article...").unwrap();
    /// ```
    pub fn new_long_form(content: &str) -> Result<Self> {
        Self::new(content, MAX_CONTENT_LENGTH)
            .context("Failed to create long-form content")
    }

    /// Creates a new TextContent instance for short-form content like titles
    /// or summaries. This applies stricter length constraints.
    ///
    /// # Arguments
    /// * `content` - The text content to validate
    ///
    /// # Example
    /// ```
    /// use your_crate::TextContent;
    ///
    /// let title = TextContent::new_short_form("Article Title").unwrap();
    /// ```
    pub fn new_short_form(content: &str) -> Result<Self> {
        Self::new(content, MAX_SHORT_CONTENT_LENGTH)
            .context("Failed to create short-form content")
    }

    /// Internal function that performs the actual validation and creation.
    /// This ensures consistent validation rules across different content types.
    fn new(content: &str, max_length: usize) -> Result<Self> {
        // First, normalize whitespace by trimming
        let trimmed = content.trim();

        // Perform our validation checks in order of complexity
        if trimmed.is_empty() {
            bail!("Content cannot be empty");
        }

        if trimmed.len() > max_length {
            bail!("Content exceeds maximum length of {} characters", max_length);
        }

        if !trimmed.validate_non_control_character() {
            bail!("Content contains invalid control characters");
        }

        if is_html(trimmed) {
            bail!("Content cannot contain HTML");
        }

        // Normalize Unicode characters to ensure consistent representation
        let normalized = trimmed.nfkc().collect::<String>();

        Ok(Self {
            text_content: normalized,
        })
    }

    /// Returns the validated content as a string slice
    pub fn as_str(&self) -> &str {
        &self.text_content
    }

    /// Returns the length of the content in characters
    pub fn len(&self) -> usize {
        self.text_content.len()
    }

    /// Returns whether the content is empty
    /// This should always return false since we validate against empty content
    pub fn is_empty(&self) -> bool {
        self.text_content.is_empty()
    }
}

/// Implements Display to allow printing the text content
impl fmt::Display for TextInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text_content)
    }
}

/// Allows using TextContent wherever a string reference is needed
impl AsRef<str> for TextInput {
    fn as_ref(&self) -> &str {
        &self.text_content
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_content() {
        let valid_contents = vec![
            "Simple text",
            "Text with numbers 123",
            "Text with symbols !@#",
            "Text with unicode ñáéíóú",
            " Text with whitespace  ",  // Should be trimmed
        ];

        for content in valid_contents {
            let result = TextInput::new_short_form(content);
            assert!(result.is_ok(), "Should accept valid content: {}", content);
        }
    }

    #[test]
    fn test_invalid_content() {
        let binding = "a".repeat(MAX_SHORT_CONTENT_LENGTH + 1);
        let invalid_contents = vec![
            "",  // Empty
            "   ",  // Only whitespace
            "<p>HTML content</p>",
            &binding,  // Too long
            "Text with null\0character",  // Control character
        ];

        for content in invalid_contents {
            let result = TextInput::new_short_form(content);
            assert!(result.is_err(), "Should reject invalid content: {}", content);
        }
    }

    #[test]
    fn test_content_normalization() {
        let content = TextInput::new_short_form("  Normal Text  ").unwrap();
        assert_eq!(content.as_str(), "Normal Text");
    }

    #[test]
    fn test_content_length_limits() {
        // Test short form content
        let short_content = "A".repeat(MAX_SHORT_CONTENT_LENGTH);
        assert!(TextInput::new_short_form(&short_content).is_ok());

        // Test long form content
        let long_content = "A".repeat(MAX_CONTENT_LENGTH);
        assert!(TextInput::new_long_form(&long_content).is_ok());
    }

    #[test]
    fn test_unicode_normalization() {
        let special_chars = TextInput::new_short_form("café").unwrap();
        // Here we ensure the content is properly normalized
        assert_eq!(special_chars.as_str().chars().count(), 4);
    }

    #[test]
    fn test_display_and_asref() {
        let content = TextInput::new_short_form("Test content").unwrap();

        // Test Display implementation
        assert_eq!(format!("{}", content), "Test content");

        // Test AsRef implementation
        let reference: &str = content.as_ref();
        assert_eq!(reference, "Test content");
    }
}