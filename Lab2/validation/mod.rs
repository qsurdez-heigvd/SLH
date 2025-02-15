//! Root module for the validation system
//! This file exposes the public API and re-exports commonly used types

mod types;
mod text;
mod file;
pub mod validators;

pub use types::{ValidationType, ValidatedInput, FileType};
pub use text::TextValidator;
pub use file::FileValidator;

// Constants that are used across the validation system
pub const MAX_USERNAME_LENGTH: usize = 64;
pub const MAX_PASSWORD_LENGTH: usize = 128;
pub const MIN_PASSWORD_LENGTH: usize = 8;
pub const MAX_CONTENT_LENGTH: usize = 2_000;
pub const MAX_SHORT_CONTENT_LENGTH: usize = 250;