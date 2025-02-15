//! File validation implementation

use super::types::{FileType, FileContent, ValidatedInput, ValidationType};
use super::validators::file as file_validators;

pub struct FileValidator {
    input: FileContent,
    max_file_size: Option<usize>,
    allowed_file_types: Vec<FileType>,
    max_image_dimensions: Option<(u32, u32)>,
}

impl FileValidator {
    /// Creates a new validator for file input
    pub fn for_file(content: Vec<u8>, filename: String, file_type: FileType) -> Self {
        Self {
            input: FileContent {
                content,
                filename,
                mime_type: None,
                file_type,
            },
            max_file_size: None,
            allowed_file_types: Vec::new(),
            max_image_dimensions: None
        }
    }

    /// Sets maximum allowed file size
    pub fn max_file_size(mut self, size: usize) -> Self {
        self.max_file_size = Some(size);
        self
    }

    /// Sets allowed image dimensions
    pub fn max_image_dimensions(mut self, width: u32, height: u32) -> Self {
        self.max_image_dimensions = Some((width, height));
        self
    }

    /// Performs file validation according to configured rules
    pub fn validate(self, validation_type: ValidationType) -> Result<ValidatedInput> {
        let file = self.input;

        // Validate file extension
        file_validators::validate_extension(&file.filename, &[file.file_type])?;

        // Validate file size if specified
        if let Some(max_size) = self.max_file_size {
            file_validators::validate_file_size(&file.content, max_size)?;
        }

        // Perform type-specific validations
        match file.file_type {
            FileType::Jpeg => {
                file_validators::validate_jpeg_integrity(&file.content)?;

                if let Some((max_width, max_height)) = self.max_image_dimensions {
                    file_validators::validate_image_dimensions(
                        &file.content,
                        max_width,
                        max_height,
                    )?;
                }
            }
            // Add other file type validations as needed
            _ => {}
        }

        Ok(ValidatedInput::File(file))
    }
}