//! Text validation implementation

use super::types::{ValidationType, ValidatedInput};
use super::validators::text as text_validators;
use ammonia::{clean, is_html};
use anyhow::bail;

pub struct TextValidator {
    input: String,
    max_length: Option<usize>,
    min_length: Option<usize>,
    allow_whitespace: bool,
    normalize_unicode: bool,
    allow_html: bool,
    sanitize_html: bool,
}

impl TextValidator {
    /// Creates a new validator for text input
    pub fn for_text(input: String) -> Self {
        Self {
            input,
            max_length: None,
            min_length: None,
            allow_whitespace: true,
            normalize_unicode: false,
            allow_html: false,
            sanitize_html: false,
        }
    }

    /// Performs text validation according to configured rules
    pub fn validate(self, validation_type: ValidationType) -> Result<ValidatedInput> {
        // First perform common text validations
        let processed_text = self.validate_text_common()?;

        // Then perform specific validations based on type
        match validation_type {
            ValidationType::Email => {
                text_validators::validate_email(&processed_text)?;
            }
            ValidationType::Username => {
                text_validators::validate_username(&processed_text)?;
            }
            ValidationType::Password => {
                text_validators::validate_password_strength(&processed_text)?;
            }
            ValidationType::Html => {
                if !self.allow_html && is_html(&processed_text) {
                    bail!("HTML content is not allowed");
                }
                if self.sanitize_html {
                    return Ok(ValidatedInput::Text(clean(&processed_text)));
                }
            }
            _ => bail!("Invalid validation type for text input"),
        }

        Ok(ValidatedInput::Text(processed_text))
    }

    /// Common validation logic for text inputs
    fn validate_text_common(&self) -> Result<String> {
        let input_str = self.input.as_str();

        if input_str.is_empty() {
            bail!("Input cannot be empty");
        }

        if let Some(max) = self.max_length {
            if input_str.len() > max {
                bail!("Input exceeds maximum length of {}", max);
            }
        }

        if let Some(min) = self.min_length {
            if input_str.len() < min {
                bail!("Input is shorter than minimum length of {}", min);
            }
        }

        // Normalize Unicode if requested
        let processed = if self.normalize_unicode {
            input_str.nfkc().collect::<String>()
        } else {
            input_str.to_string()
        };

        Ok(processed)
    }
}