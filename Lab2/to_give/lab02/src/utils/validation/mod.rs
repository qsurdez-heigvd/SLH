//! Root module for the validation system.
//! Exposes the public API for input validation.

mod types;
mod constants;

// Re-export commonly used types and functions
pub use constants::*;
pub use types::{EmailInput, FileInput, TextInput};
