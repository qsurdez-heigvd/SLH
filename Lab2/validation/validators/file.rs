//! File-specific validation functions

use std::path::Path;
use anyhow::bail;
use magic::{Cookie};
use image::ImageFormat;
use super::super::types::FileType;

/// Validates a file's extension
pub fn validate_extension(filename: &str, allowed_types: &[FileType]) -> Result<()> {
    let extension = Path::new(filename)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_lowercase());

    let extension = extension.ok_or_else(|| {
        anyhow::anyhow!("File must have an extension")
    })?;

    // Check if the extension matches any of the allowed types
    if !allowed_types.iter().any(|ft| {
        ft.allowed_extensions()
            .iter()
            .any(|&allowed| allowed == extension)
    }) {
        let allowed_extensions: Vec<_> = allowed_types
            .iter()
            .flat_map(|ft| ft.allowed_extensions())
            .collect();

        bail!("Invalid file extension. Allowed extensions: {}",
                  allowed_extensions.join(", "));
    }

    Ok(())
}

/// Validates image dimensions
pub fn validate_image_dimensions(
    content: &[u8],
    max_width: u32,
    max_height: u32,
) -> Result<()> {
    let img = image::load_from_memory(content)
        .context("Failed to load image")?;

    let dimensions = img.dimensions();
    if dimensions.0 > max_width || dimensions.1 > max_height {
        bail!(
                "Image dimensions ({} x {}) exceed maximum allowed ({} x {})",
                dimensions.0,
                dimensions.1,
                max_width,
                max_height
            );
    }

    Ok(())
}

/// Validates file content matches its purported type
pub fn validate_content_type(content: &[u8], expected_type: FileType) -> Result<()> {
    // Initialize libmagic cookie for MIME type detection
    let flags = magic::cookie::Flags::EXTENSION;
    let cookie = Cookie::open(flags)
        .context("Failed to initialize magic cookie")?;
    cookie.load::<&str>(&[])
        .context("Failed to load magic database")?;

    let detected_mime = cookie
        .buffer(content)
        .context("Failed to detect MIME type")?;

    if detected_mime != expected_type {
        bail!(
                "File content does not match expected type. Expected {}, got {}",
                expected_type,
                detected_mime
            );
    }

    Ok(())
}

/// Validates JPEG image integrity
pub fn validate_jpeg_integrity(content: &[u8]) -> Result<()> {
    // Try to decode the image to verify its integrity
    match image::load_from_memory_with_format(content, ImageFormat::Jpeg) {
        Ok(_) => Ok(()),
        Err(e) => bail!("Invalid JPEG image: {}", e),
    }
}

/// Validates image file size
pub fn validate_file_size(content: &[u8], max_size: usize) -> Result<()> {
    if content.len() > max_size {
        bail!(
                "File size {} bytes exceeds maximum allowed size of {} bytes",
                content.len(),
                max_size
            );
    }
    Ok(())
}
