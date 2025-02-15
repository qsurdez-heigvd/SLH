//! Type definitions for the validation system

mod file_input;
mod email_input;
mod text_input;

// Re-export commonly used types and functions
pub use email_input::EmailInput;
pub use file_input::FileInput;
pub use text_input::TextInput;