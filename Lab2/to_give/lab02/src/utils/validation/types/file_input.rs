//! Provides a secure way to handle and validate file content, particularly focused on
//! image files. This module ensures that files meet our security and format requirements
//! before they can be processed further in the application.

use std::path::Path;
use anyhow::{bail, Context, Result};
use image::{ImageFormat, GenericImageView};

/// Represents the maximum allowed file size (1MB)
const MAX_FILE_SIZE: usize = 1 * 1024 * 1024;

/// Represents the maximum allowed image dimensions
const MAX_IMAGE_DIMENSIONS: (u32, u32) = (4096, 4096);

/// A validated file content wrapper that ensures the contained file meets our
/// security and format requirements. This type provides guarantees about the
/// file's format, size, and integrity.
#[derive(Debug, Clone)]
pub struct FileInput {
    // The actual bytes of the file content
    content: Vec<u8>,
    // The sanitized and validated filename
    filename: String,
    // The dimensions if this is an image file
    dimensions: Option<(u32, u32)>,
}

impl FileInput {
    /// Creates a new FileContent instance after performing comprehensive validation
    /// of both the file content and filename. This ensures that files are safe to
    /// process before they enter our system.
    ///
    /// # Arguments
    /// * `content` - The raw bytes of the file
    /// * `filename` - The original filename (will be sanitized)
    ///
    /// # Returns
    /// * `Ok(FileContent)` if validation passes
    /// * `Err` with a descriptive message if any validation fails
    ///
    /// # Example
    /// ```
    /// use your_crate::FileContent;
    ///
    /// let content = std::fs::read("test.jpg")?;
    /// let file = FileContent::new(&content, "test.jpg")?;
    /// ```
    pub fn new(content: &[u8], filename: &str) -> Result<Self> {
        // First, validate the file size to prevent DOS attacks
        Self::validate_file_size(content)?;

        // Sanitize and validate the filename
        let sanitized_filename = Self::sanitize_filename(filename)
            .context("Failed to process filename")?;

        // Validate the file extension
        let extension = Self::get_file_extension(&sanitized_filename)
            .context("Failed to get file extension")?;

        if !Self::is_valid_extension(&extension) {
            bail!("File must have a .jpg or .jpeg extension");
        }

        // Validate the image format using multiple checks for security
        Self::validate_image_format(content)
            .context("Failed to validate image format")?;

        // Load the image to validate its integrity and dimensions
        let dimensions = Self::validate_image_integrity(content)
            .context("Failed to validate image integrity")?;

        Ok(Self {
            content: content.to_vec(),
            filename: sanitized_filename,
            dimensions: Some(dimensions),
        })
    }

    /// Validates that the file size is within acceptable limits
    fn validate_file_size(content: &[u8]) -> Result<()> {
        if content.is_empty() {
            bail!("File content cannot be empty");
        }
        if content.len() > MAX_FILE_SIZE {
            bail!("File size exceeds maximum allowed size of {} bytes", MAX_FILE_SIZE);
        }
        Ok(())
    }

    /// Sanitizes and validates the filename to prevent path traversal attacks
    fn sanitize_filename(filename: &str) -> Result<String> {
        let filename = filename.trim();

        if filename.is_empty() {
            bail!("Filename cannot be empty");
        }

        // Remove any path components for security
        let filename = Path::new(filename)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid filename"))?;

        Ok(filename.to_string())
    }

    /// Extracts and validates the file extension
    fn get_file_extension(filename: &str) -> Result<String> {
        Path::new(filename)
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|s| s.to_lowercase())
            .ok_or_else(|| anyhow::anyhow!("Missing file extension"))
    }

    /// Checks if the file extension is allowed
    fn is_valid_extension(extension: &str) -> bool {
        matches!(extension, "jpg" | "jpeg")
    }

    /// Validates that the content is actually a JPEG image
    fn validate_image_format(content: &[u8]) -> Result<()> {
        match image::guess_format(content) {
            Ok(format) if format == ImageFormat::Jpeg => Ok(()),
            Ok(_) => bail!("File must be in JPEG format"),
            Err(_) => bail!("Unable to determine file format"),
        }
    }

    /// Validates the image integrity and dimensions
    fn validate_image_integrity(content: &[u8]) -> Result<(u32, u32)> {
        let img = image::load_from_memory_with_format(content, ImageFormat::Jpeg)
            .context("Failed to load image")?;

        let dimensions = img.dimensions();

        // Validate image dimensions
        if dimensions.0 > MAX_IMAGE_DIMENSIONS.0 || dimensions.1 > MAX_IMAGE_DIMENSIONS.1 {
            bail!(
                "Image dimensions ({} x {}) exceed maximum allowed ({} x {})",
                dimensions.0, dimensions.1,
                MAX_IMAGE_DIMENSIONS.0, MAX_IMAGE_DIMENSIONS.1
            );
        }

        Ok(dimensions)
    }

    /// Returns the file content as a byte slice
    pub fn content(&self) -> &[u8] {
        &self.content
    }

    /// Returns the sanitized filename
    pub fn filename(&self) -> &str {
        &self.filename
    }

    /// Returns the image dimensions if available
    pub fn dimensions(&self) -> Option<(u32, u32)> {
        self.dimensions
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use super::*;

    // Helper function to create test data
    fn create_test_jpeg() -> Vec<u8> {
        // Create a small valid JPEG for testing
        let img = image::RgbImage::new(100, 100);

        // Create a buffer with a Cursor for seeking capability
        let mut buffer = Vec::new();
        let mut cursor = Cursor::new(&mut buffer);

        // Write the image to our seekable buffer
        img.write_to(&mut cursor, ImageFormat::Jpeg)
            .expect("Failed to create test image");

        buffer
    }

    #[test]
    fn test_valid_jpeg_creation() {
        let content = create_test_jpeg();
        let result = FileInput::new(&content, "test.jpg");
        assert!(result.is_ok());
    }

    #[test]
    fn test_filename_sanitization() {
        let content = create_test_jpeg();

        // Test various filenames
        let cases = vec![
            ("test.jpg", true),
            ("../test.jpg", true),  // Path traversal attempt
            ("test.jpeg", true),
            ("test.png", false),
            ("", false),
            ("test", false),
        ];

        for (filename, should_succeed) in cases {
            let result = FileInput::new(&content, filename);
            assert_eq!(
                result.is_ok(),
                should_succeed,
                "Failed for filename: {}", filename
            );
        }
    }

    #[test]
    fn test_file_size_limits() {
        // Test empty file
        let result = FileInput::new(&[], "test.jpg");
        assert!(result.is_err());

        // Test file that's too large
        let large_content = vec![0; MAX_FILE_SIZE + 1];
        let result = FileInput::new(&large_content, "test.jpg");
        assert!(result.is_err());
    }

    #[test]
    fn test_image_integrity() {
        // First test: Completely invalid data
        let invalid_data = vec![0u8; 100];  // Just zeros
        let result = FileInput::new(&invalid_data, "test.jpg");
        assert!(result.is_err(), "Should reject completely invalid JPEG data");

        // Second test: Corrupt the JPEG header
        let mut content = create_test_jpeg();
        content[0] = 0x00;  // Corrupt the JPEG SOI marker (should be 0xFF 0xD8)
        let result = FileInput::new(&content, "test.jpg");
        assert!(result.is_err(), "Should reject JPEG with invalid header");

        // Third test: Corrupt the JPEG footer
        let mut content = create_test_jpeg();
        if content.len() >= 15 {
            content.truncate(2);  // Corrupt the JPEG EOI marker
            let result = FileInput::new(&content, "test.jpg");
            assert!(result.is_err(), "Should reject JPEG with invalid footer");
        }

    }
}