use std::{io::Cursor, path::Path};

use image::{GenericImageView, ImageFormat, ImageReader};
use serde_json::json;

use crate::{
    blob,
    model::{DriveFile, FileMetadata},
};

/// Derived-data work is best-effort and must never be able to size process
/// memory from the advertised 2 GiB upload ceiling.
pub(crate) const MAX_DERIVED_INPUT_BYTES: u64 = 32 * 1024 * 1024;
pub(super) const MAX_EXTRACTED_TEXT_BYTES: usize = 2 * 1024 * 1024;
const MAX_OFFICE_ARCHIVE_ENTRIES: usize = 1024;
pub(super) const MAX_OFFICE_ENTRY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_OFFICE_EXPANDED_BYTES: u64 = 16 * 1024 * 1024;
const MAX_OFFICE_COMPRESSION_RATIO: u64 = 200;
const MAX_IMAGE_DIMENSION: u32 = 8192;
const MAX_IMAGE_PIXELS: u64 = 20_000_000;
const MAX_IMAGE_DECODE_ALLOC: u64 = 128 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct GeneratedPreview {
    pub kind: String,
    pub content: String,
    pub thumbnail_hash: Option<String>,
    pub thumbnail_content_type: Option<String>,
    pub thumbnail_bytes: i64,
    pub width: Option<i64>,
    pub height: Option<i64>,
    pub status: String,
    pub thumbnail_publication: Option<blob::BlobFilePublication>,
}

pub(super) fn generate_file_preview(
    data_dir: &Path,
    file: &DriveFile,
    bytes: &[u8],
) -> Result<GeneratedPreview, String> {
    let extension = file_extension(&file.name);
    if is_image_extension(&extension) {
        return generate_image_preview(data_dir, bytes)
            .or_else(|error| Ok(unsupported_preview("Image", Some(error))));
    }
    if extension == "pdf" {
        return Ok(unsupported_preview("PDF", None));
    }
    if let Some(format) = office_format(&extension) {
        return Ok(generate_office_preview(bytes, format));
    }
    if is_video_extension(&extension) {
        return Ok(unsupported_preview("Video", None));
    }
    if is_text_extension(&extension) || looks_like_text(bytes) {
        return Ok(text_excerpt_preview(&String::from_utf8_lossy(bytes)));
    }
    Ok(unsupported_preview("File", None))
}

pub(super) fn extract_search_text(file_name: &str, bytes: &[u8]) -> Result<Option<String>, String> {
    if bytes.len() as u64 > MAX_DERIVED_INPUT_BYTES {
        return Err(format!(
            "file exceeds {} MiB derived-data processing limit",
            MAX_DERIVED_INPUT_BYTES / (1024 * 1024)
        ));
    }
    let extension = file_extension(file_name);
    if extension == "pdf" {
        return Ok(non_empty_text(extract_pdf_text(bytes)));
    }
    if let Some(format) = office_format(&extension) {
        return match format {
            OfficeDocumentFormat::LegacyBinary => Ok(None),
            OfficeDocumentFormat::OpenXml | OfficeDocumentFormat::OpenDocument => {
                extract_office_text(bytes, format).map(non_empty_text)
            }
        };
    }
    if is_text_extension(&extension) || looks_like_text(bytes) {
        return Ok(non_empty_text(String::from_utf8_lossy(bytes).to_string()));
    }
    Ok(None)
}

pub(super) fn empty_file_metadata() -> FileMetadata {
    FileMetadata {
        labels: Vec::new(),
        custom_metadata: json!({}),
        size_bytes: None,
        folder_size_bytes: None,
    }
}

fn preview_excerpt(content: &str) -> String {
    content.chars().take(240).collect()
}

fn generate_office_preview(bytes: &[u8], format: OfficeDocumentFormat) -> GeneratedPreview {
    if matches!(format, OfficeDocumentFormat::LegacyBinary) {
        return unavailable_preview(
            "Legacy binary Office document preview is unavailable. Legacy .doc, .xls, and .ppt files are not supported for text extraction or previews.".to_string(),
        );
    }
    match extract_office_text(bytes, format).map(non_empty_text) {
        Ok(Some(content)) => text_excerpt_preview(&content),
        Ok(None) => unavailable_preview(format!(
            "{} preview is unavailable because the document contains no readable text.",
            format.display_name()
        )),
        Err(_) => unavailable_preview(format!(
            "{} preview is unavailable because its document package could not be read.",
            format.display_name()
        )),
    }
}

fn text_excerpt_preview(content: &str) -> GeneratedPreview {
    GeneratedPreview {
        kind: "text_excerpt".to_string(),
        content: preview_excerpt(content),
        thumbnail_hash: None,
        thumbnail_content_type: None,
        thumbnail_bytes: 0,
        width: None,
        height: None,
        status: "ready".to_string(),
        thumbnail_publication: None,
    }
}

fn extract_pdf_text(bytes: &[u8]) -> String {
    let raw = String::from_utf8_lossy(bytes);
    let mut output = String::new();
    let mut in_literal = false;
    let mut escaped = false;
    for character in raw.chars() {
        if in_literal {
            if escaped {
                output.push(character);
                escaped = false;
                continue;
            }
            if character == '\\' {
                escaped = true;
                continue;
            }
            if character == ')' {
                in_literal = false;
                output.push(' ');
                continue;
            }
            output.push(character);
            if output.len() >= MAX_EXTRACTED_TEXT_BYTES {
                break;
            }
        } else if character == '(' {
            in_literal = true;
        }
    }
    if output.trim().is_empty() {
        printable_text(&raw)
    } else {
        output
    }
}

pub(super) fn non_empty_text(value: String) -> Option<String> {
    let mut normalized = String::new();
    for word in value.split_whitespace() {
        let separator = usize::from(!normalized.is_empty());
        if normalized.len() + separator + word.len() > MAX_EXTRACTED_TEXT_BYTES {
            break;
        }
        if separator == 1 {
            normalized.push(' ');
        }
        normalized.push_str(word);
    }
    (!normalized.is_empty()).then_some(normalized)
}

pub(super) fn generate_image_preview(
    data_dir: &Path,
    bytes: &[u8],
) -> Result<GeneratedPreview, String> {
    let reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|error| error.to_string())?;
    let (declared_width, declared_height) = reader
        .into_dimensions()
        .map_err(|error| error.to_string())?;
    if declared_width > MAX_IMAGE_DIMENSION
        || declared_height > MAX_IMAGE_DIMENSION
        || u64::from(declared_width).saturating_mul(u64::from(declared_height)) > MAX_IMAGE_PIXELS
    {
        return Err("image dimensions exceed preview safety limit".to_string());
    }

    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
    limits.max_alloc = Some(MAX_IMAGE_DECODE_ALLOC);
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|error| error.to_string())?;
    reader.limits(limits);
    let image = reader.decode().map_err(|error| error.to_string())?;
    let (width, height) = image.dimensions();
    let thumbnail = image.thumbnail(512, 512);
    let mut encoded = Cursor::new(Vec::new());
    thumbnail
        .write_to(&mut encoded, ImageFormat::Png)
        .map_err(|error| error.to_string())?;
    let publication = blob::put_blob_with_outcome(data_dir, &encoded.into_inner())
        .map_err(|error| error.to_string())?;
    let thumbnail_bytes = i64::try_from(publication.size)
        .map_err(|_| "generated thumbnail exceeds the supported size".to_string())?;
    Ok(GeneratedPreview {
        kind: "image_thumbnail".to_string(),
        content: "Image preview ready.".to_string(),
        thumbnail_hash: Some(publication.hash.clone()),
        thumbnail_content_type: Some("image/png".to_string()),
        thumbnail_bytes,
        width: Some(i64::from(width)),
        height: Some(i64::from(height)),
        status: "ready".to_string(),
        thumbnail_publication: Some(publication),
    })
}

fn unsupported_preview(kind: &str, error: Option<String>) -> GeneratedPreview {
    let detail = error.map(|error| format!(": {error}")).unwrap_or_default();
    unavailable_preview(format!("{kind} preview is not generated yet{detail}."))
}

fn unavailable_preview(content: String) -> GeneratedPreview {
    GeneratedPreview {
        kind: "preview_unavailable".to_string(),
        content,
        thumbnail_hash: None,
        thumbnail_content_type: None,
        thumbnail_bytes: 0,
        width: None,
        height: None,
        status: "unsupported".to_string(),
        thumbnail_publication: None,
    }
}

fn file_extension(name: &str) -> String {
    name.rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default()
}

fn is_image_extension(extension: &str) -> bool {
    matches!(extension, "gif" | "jpg" | "jpeg" | "png" | "webp")
}

fn is_video_extension(extension: &str) -> bool {
    matches!(
        extension,
        "avi" | "m4v" | "mov" | "mp4" | "mpeg" | "mpg" | "webm"
    )
}

fn is_text_extension(extension: &str) -> bool {
    matches!(
        extension,
        "css"
            | "csv"
            | "go"
            | "html"
            | "js"
            | "json"
            | "log"
            | "md"
            | "py"
            | "rs"
            | "toml"
            | "ts"
            | "txt"
            | "xml"
            | "yaml"
            | "yml"
    )
}

fn looks_like_text(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes)
        .map(|content| {
            !content
                .chars()
                .take(1000)
                .any(|character| character == '\0')
        })
        .unwrap_or(false)
}

mod office;
#[cfg(test)]
mod tests;

use office::{extract_office_text, office_format, printable_text, OfficeDocumentFormat};
