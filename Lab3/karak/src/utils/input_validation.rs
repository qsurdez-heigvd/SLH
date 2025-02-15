use derive_more::derive::Display;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use regex::Regex;
use gtin_validate::gtin13;
use inquire::Text;
use zxcvbn::{zxcvbn, Score};

// Regex for username
static USERNAME_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z][a-zA-Z0-9_]{2,19}$")
        .expect("Failed to compile username regex")
});

static MIN_SCORE: Score = Score::Three;


/// This function checks if the given password is valid
/// Returns true if the password is strong enough, false otherwise
fn password_validation(password: &str, username: &str) -> bool {
    // First check: password should not be the same as username
    if password.eq_ignore_ascii_case(username) {
        return false;
    }

    // Second check: password must be between 8 to 64 characters
    if password.len() <= 8 || password.len() >= 64 {
        return false;
    }

    // Use crate zxcvbn for checking password entropy
    let estimate = zxcvbn(password, &[username]);

    estimate.score() >= MIN_SCORE
}

/// Interactively prompts the user for a password
pub fn password_input_validation(username: &str) -> String {
    loop {
        print!("Enter your password: ");
        // let password = rpassword::read_password().unwrap();

        let password = inquire::Password::new("Enter your password: ")
            .prompt()
            .unwrap_or("".to_string());

        if password_validation(&password, username) {
            return password;
        }

        println!("Your password must be between 8 to 64 characters long [8-64]");
        println!("Your password must be different from your username");
        println!("Your password must be unguessable");

        let entropy = zxcvbn(password.as_str(), &[username]);

        // If we reach here, the MIN_SCORE is not attained in our password_validation
        // function
        if let Some(feedback) = entropy.feedback() {
            if let Some(warning) = feedback.warning() {
                println!("\nWarning: {}", warning);
            }
            if !feedback.suggestions().is_empty() {
                println!("Suggestions: ");
                for suggestion in feedback.suggestions() {
                    println!("- {}", suggestion);
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Display, Error)]
pub struct InvalidInput;

/// Wrapper type for a username thas has been validated
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Display)]
pub struct Username(String);

impl TryFrom<String> for Username {
    type Error = InvalidInput;

    fn try_from(username: String) -> Result<Self, Self::Error> {
        username_validation(&username)?;
        Ok(Self(username))
    }
}

impl TryFrom<&str> for Username {
    type Error = InvalidInput;

    fn try_from(username: &str) -> Result<Self, Self::Error> {
        username_validation(username)?;
        Ok(Self(username.to_owned()))
    }
}

impl AsRef<str> for Username {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

fn username_validation(username: &str) -> Result<(), InvalidInput> {
    if USERNAME_REGEX.is_match(username) {
        Ok(())
    } else {
        Err(InvalidInput)
    }
}

pub fn username_input_validation(message: &str) -> Result<Username, InvalidInput> {
    let username = Text::new(message)
        .prompt()
        .unwrap();
    Username::try_from(username)
}

/// Wrapper type for an AVS number that has been validated
#[derive(Debug, Display, Serialize, Deserialize, Hash)]
pub struct AVSNumber(String);

impl TryFrom<String> for AVSNumber {
    type Error = InvalidInput;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if validate_avs_number(&value) {
            Ok(AVSNumber(value))
        } else {
            Err(InvalidInput)
        }
    }
}

impl TryFrom<&str> for AVSNumber {
    type Error = InvalidInput;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if validate_avs_number(value) {
            Ok(AVSNumber(value.to_string()))
        } else {
            Err(InvalidInput)
        }
    }
}

fn validate_avs_number(avs_number: &str) -> bool {

    // Remove the dots
    let clean_number: String = avs_number.chars()
        .filter(|c| c.is_digit(10))
        .collect();

    // Check that it starts with the swiss number
    if !clean_number.starts_with("756") {
        return false;
    }

    // Check with crate gtin13 if control number is correct
    if !gtin13::check(&clean_number) {
        return false;
    }

    return true;
}

#[cfg(test)]
mod tests {
    use super::*;

    mod username_wrapper_tests {
        use super::*;

        #[test]
        fn test_valid_username() {
            let valid_cases = vec![
                "alice123",
                "Bob_user",
                "developer123",
                "john_doe_42"
            ];

            for username in valid_cases {
                assert!(Username::try_from(username).is_ok(),
                        "Valid username {} was rejected !", username);
            }
        }

        #[test]
        fn test_invalid_username() {
            let invalid_cases = vec![
                "a",
                "123starts_with_numbers",
                "_starts_with_underscore",
                "very_very_long_username_that_exceeds_limit",
                "special@character",
                "has space"
            ];

            for username in invalid_cases {
                assert!(Username::try_from(username).is_err(),
                        "Invalid username {} was approved !", username);
            }
        }


        #[test]
        fn test_username_from_string() {
            assert!(Username::try_from("valid").is_ok());
            assert!(Username::try_from("1234").is_err());
        }

        #[test]
        fn test_username_display() {
            let username = Username::try_from("test_user").unwrap();
            assert_eq!(username.to_string(), "test_user");
        }

        #[test]
        fn test_username_as_ref() {
            let username = Username::try_from("test_user").unwrap();
            assert_eq!(username.as_ref(), "test_user");
        }
    }

    mod avs_number_tests {
        use super::*;


        #[test]
        fn test_valid_avs_number() {
            let valid_cases = vec![
                "756.9217.0769.85",
                "756.3047.5009.62"
            ];

            for number in valid_cases {
                assert!(AVSNumber::try_from(number).is_ok(),
                        "Valid AVS number {} was rejected !", number)
            }
        }

        #[test]
        fn test_invalid_avs_number() {
            let invalid_cases = vec![
                "756.1234.5678.98",  // Invalid check digit
                "123.4567.8901.23",  // Wrong prefix
                "756.1234.5678",     // Incomplete
                "756.1234.5678.901", // Too long
                "756.abcd.efgh.ij",  // Non-numeric
                "....",              // Just dots
                "",                  // Empty string
            ];

            for number in invalid_cases {
                assert!(AVSNumber::try_from(number).is_err(),
                        "Invalid AVS number {} was accepted !", number)
            }
        }

        mod password_tests {
            use super::*;

            #[test]
            fn test_password_strength_levels() {
                let username = "testuser";

                // Test different strength levels
                let test_cases = vec![
                    // (password, expected_valid)
                    ("short", false),                    // Too short
                    ("password123", false),              // Too common
                    ("abcdefghijklm", false),           // No complexity
                    ("StrongP@ssw0rd!", true),           // Good complexity
                    ("Tr0ub4dour&3!", true),             // Strong with special chars
                ];

                for (password, expected_valid) in test_cases {
                    assert_eq!(password_validation(password, username), expected_valid,
                               "Password '{}' validation result was unexpected", password);
                }
            }

            #[test]
            fn test_password_username_correlation() {
                let username = "testuser";

                // Test passwords similar to username
                assert!(!password_validation(username, username),
                        "Password identical to username was accepted");
                assert!(!password_validation(&username.to_uppercase(), username),
                        "Password similar to username (uppercase) was accepted");
                assert!(!password_validation(&format!("{}123", username), username),
                        "Password containing username was accepted");
            }

            #[test]
            fn test_password_length_boundaries() {
                let username = "testuser";

                // Test length boundaries
                assert!(!password_validation("1234567", username),  // 7 chars
                        "Password shorter than minimum length was accepted");

                // Even a long password needs to meet complexity requirements
                let long_weak_password = "a".repeat(65);
                assert!(!password_validation(&long_weak_password, username),
                        "Too long password was accepted");
            }
        }
    }
}