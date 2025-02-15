//! Text-specific validation functions

use anyhow::bail;
use once_cell::sync::Lazy;
use regex::Regex;

/// Validates email addresses according to HTML5 specification
pub fn validate_email(email: &str) -> Result<()> {
    static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$").unwrap()
    });

    if !EMAIL_REGEX.is_match(email) {
        bail!("Invalid email format");
    }
    Ok(())
}

/// Validates username format allowing only safe characters
pub fn validate_username(username: &str) -> Result<()> {
    static USERNAME_REGEX: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$").unwrap()
    });

    if !USERNAME_REGEX.is_match(username) {
        bail!("Username must contain only letters, numbers, underscores, and hyphens, and start with a letter or number");
    }
    Ok(())
}

/// Validates password strength using multiple criteria
pub fn validate_password_strength(password: &str) -> Result<()> {
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_number = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    if !has_uppercase || !has_lowercase || !has_number || !has_special {
        bail!("Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character");
    }
    Ok(())
}