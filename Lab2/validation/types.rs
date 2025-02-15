//! Core types used throughout the validation system


/// Represents all possible types of validation that our system can perform.
/// This helps us track what kind of validation was applied to any given input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationType {
    // Text-based validations
    Username,
    Password,
    Email,
    LongContent,
    ShortContent,
    Html,

    // File-based validations
    ImageFile(FileType),
    DocumentFile(FileType),
    GenericFile(FileType),
}

/// Represents the specific type of file being validated.
/// This allows us to enforce different rules for different file types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Jpeg,
    Png,
    Pdf,
    // We can add more file types as needed
}

/// A secure wrapper that holds validated input of any supported type.
/// This ensures that any data that's been validated maintains its validated status.
#[derive(Debug, Clone)]
pub enum ValidatedInput {
    Text(String),
    File(FileContent),
}

/// Represents file content along with its metadata
#[derive(Debug, Clone)]
pub struct FileContent {
    pub(crate) content: Vec<u8>,
    pub(crate) filename: String,
    pub(crate) mime_type: Option<String>,
    pub(crate) file_type: FileType,
}