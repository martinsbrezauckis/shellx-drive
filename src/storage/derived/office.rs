use std::io::{Cursor, Read};

use super::{
    MAX_EXTRACTED_TEXT_BYTES, MAX_OFFICE_ARCHIVE_ENTRIES, MAX_OFFICE_COMPRESSION_RATIO,
    MAX_OFFICE_ENTRY_BYTES, MAX_OFFICE_EXPANDED_BYTES,
};

#[derive(Debug, Clone, Copy)]
pub(super) enum OfficeDocumentFormat {
    OpenXml,
    OpenDocument,
    LegacyBinary,
}

pub(super) fn office_format(extension: &str) -> Option<OfficeDocumentFormat> {
    match extension {
        "docx" | "xlsx" | "pptx" => Some(OfficeDocumentFormat::OpenXml),
        "odt" | "ods" | "odp" => Some(OfficeDocumentFormat::OpenDocument),
        "doc" | "xls" | "ppt" => Some(OfficeDocumentFormat::LegacyBinary),
        _ => None,
    }
}

impl OfficeDocumentFormat {
    pub(super) fn display_name(self) -> &'static str {
        match self {
            Self::OpenXml => "Office Open XML document",
            Self::OpenDocument => "OpenDocument file",
            Self::LegacyBinary => "Legacy binary Office document",
        }
    }

    fn includes_entry(self, name: &str) -> bool {
        match self {
            Self::OpenXml => {
                name.ends_with(".xml")
                    && (name.starts_with("word/")
                        || name.starts_with("xl/")
                        || name.starts_with("ppt/")
                        || name == "[content_types].xml")
            }
            Self::OpenDocument => name == "content.xml",
            Self::LegacyBinary => false,
        }
    }
}

pub(super) fn extract_office_text(
    bytes: &[u8],
    format: OfficeDocumentFormat,
) -> Result<String, String> {
    let declared_entries = preflight_office_archive_entry_count(bytes)?;
    if declared_entries > MAX_OFFICE_ARCHIVE_ENTRIES as u64 {
        return Err(format!(
            "office archive has too many entries: {declared_entries} > {MAX_OFFICE_ARCHIVE_ENTRIES}"
        ));
    }
    let reader = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader).map_err(|error| error.to_string())?;
    if archive.len() > MAX_OFFICE_ARCHIVE_ENTRIES {
        return Err(format!(
            "office archive has too many entries: {} > {MAX_OFFICE_ARCHIVE_ENTRIES}",
            archive.len()
        ));
    }
    let mut output = String::new();
    let mut expanded_bytes = 0u64;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|error| error.to_string())?;
        let name = entry.name().to_ascii_lowercase();
        if !format.includes_entry(&name) {
            continue;
        }
        let entry_size = entry.size();
        if entry_size > MAX_OFFICE_ENTRY_BYTES {
            return Err(format!("office XML entry is too large: {name}"));
        }
        expanded_bytes = expanded_bytes
            .checked_add(entry_size)
            .ok_or_else(|| "office archive expanded size overflow".to_string())?;
        if expanded_bytes > MAX_OFFICE_EXPANDED_BYTES {
            return Err("office archive expands beyond processing limit".to_string());
        }
        let compressed_size = entry.compressed_size();
        if compressed_size > 0
            && entry_size
                > compressed_size
                    .saturating_mul(MAX_OFFICE_COMPRESSION_RATIO)
                    .saturating_add(1024 * 1024)
        {
            return Err(format!(
                "office XML entry compression ratio is unsafe: {name}"
            ));
        }
        let mut xml = String::new();
        let mut limited = (&mut entry).take(MAX_OFFICE_ENTRY_BYTES.saturating_add(1));
        if limited.read_to_string(&mut xml).is_ok() {
            if xml.len() as u64 > MAX_OFFICE_ENTRY_BYTES {
                return Err(format!(
                    "office XML entry exceeded processing limit: {name}"
                ));
            }
            output.push(' ');
            output.push_str(&strip_xml_tags(&xml));
            if output.len() >= MAX_EXTRACTED_TEXT_BYTES {
                truncate_utf8_bytes(&mut output, MAX_EXTRACTED_TEXT_BYTES);
                break;
            }
        }
    }
    Ok(output)
}

fn preflight_office_archive_entry_count(bytes: &[u8]) -> Result<u64, String> {
    const EOCD_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
    const ZIP64_LOCATOR_SIGNATURE: &[u8; 4] = b"PK\x06\x07";
    const ZIP64_EOCD_SIGNATURE: &[u8; 4] = b"PK\x06\x06";
    const MAX_ZIP_COMMENT_BYTES: usize = u16::MAX as usize;

    let search_start = bytes.len().saturating_sub(22 + MAX_ZIP_COMMENT_BYTES);
    let eocd = (search_start..bytes.len().saturating_sub(21))
        .rev()
        .find(|&offset| {
            bytes.get(offset..offset + 4) == Some(EOCD_SIGNATURE.as_slice())
                && read_zip_u16(bytes, offset + 20).is_some_and(|comment_bytes| {
                    offset + 22 + usize::from(comment_bytes) == bytes.len()
                })
        })
        .ok_or_else(|| "office archive lacks a bounded ZIP end record".to_string())?;
    let disk = read_zip_u16(bytes, eocd + 4).ok_or_else(|| "invalid ZIP end record".to_string())?;
    let directory_disk =
        read_zip_u16(bytes, eocd + 6).ok_or_else(|| "invalid ZIP end record".to_string())?;
    if disk != 0 || directory_disk != 0 {
        return Err("multi-disk office archives are not supported".to_string());
    }
    let disk_entries =
        read_zip_u16(bytes, eocd + 8).ok_or_else(|| "invalid ZIP end record".to_string())?;
    let total_entries =
        read_zip_u16(bytes, eocd + 10).ok_or_else(|| "invalid ZIP end record".to_string())?;
    let directory_bytes =
        read_zip_u32(bytes, eocd + 12).ok_or_else(|| "invalid ZIP end record".to_string())?;
    let directory_offset =
        read_zip_u32(bytes, eocd + 16).ok_or_else(|| "invalid ZIP end record".to_string())?;
    let zip64 = disk_entries == u16::MAX
        || total_entries == u16::MAX
        || directory_bytes == u32::MAX
        || directory_offset == u32::MAX;
    if !zip64 {
        if disk_entries != total_entries
            || u64::from(directory_offset).saturating_add(u64::from(directory_bytes)) > eocd as u64
        {
            return Err("office archive has an invalid central directory".to_string());
        }
        return Ok(u64::from(total_entries));
    }

    let locator = eocd
        .checked_sub(20)
        .ok_or_else(|| "ZIP64 office archive lacks its locator".to_string())?;
    if bytes.get(locator..locator + 4) != Some(ZIP64_LOCATOR_SIGNATURE.as_slice()) {
        return Err("ZIP64 office archive lacks its locator".to_string());
    }
    let zip64_disk =
        read_zip_u32(bytes, locator + 4).ok_or_else(|| "invalid ZIP64 locator".to_string())?;
    let zip64_offset =
        read_zip_u64(bytes, locator + 8).ok_or_else(|| "invalid ZIP64 locator".to_string())?;
    let total_disks =
        read_zip_u32(bytes, locator + 16).ok_or_else(|| "invalid ZIP64 locator".to_string())?;
    if zip64_disk != 0 || total_disks != 1 {
        return Err("multi-disk ZIP64 office archives are not supported".to_string());
    }
    let zip64_offset = usize::try_from(zip64_offset)
        .map_err(|_| "ZIP64 end record offset is unsupported".to_string())?;
    if !zip_slice_equals(bytes, zip64_offset, ZIP64_EOCD_SIGNATURE) {
        return Err("ZIP64 office archive lacks its end record".to_string());
    }
    let record_bytes = read_zip_u64(bytes, zip64_offset + 4)
        .ok_or_else(|| "invalid ZIP64 end record".to_string())?;
    let record_end = (zip64_offset as u64)
        .checked_add(12)
        .and_then(|offset| offset.checked_add(record_bytes))
        .ok_or_else(|| "ZIP64 end record length overflow".to_string())?;
    if record_bytes < 44 || record_end > locator as u64 {
        return Err("invalid ZIP64 end record length".to_string());
    }
    let disk_entries = read_zip_u64(bytes, zip64_offset + 24)
        .ok_or_else(|| "invalid ZIP64 end record".to_string())?;
    let total_entries = read_zip_u64(bytes, zip64_offset + 32)
        .ok_or_else(|| "invalid ZIP64 end record".to_string())?;
    if disk_entries != total_entries {
        return Err("invalid ZIP64 central directory count".to_string());
    }
    Ok(total_entries)
}

fn read_zip_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    Some(u16::from_le_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

fn read_zip_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    Some(u32::from_le_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

fn read_zip_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    Some(u64::from_le_bytes(bytes.get(offset..end)?.try_into().ok()?))
}

fn zip_slice_equals(bytes: &[u8], offset: usize, expected: &[u8]) -> bool {
    offset
        .checked_add(expected.len())
        .and_then(|end| bytes.get(offset..end))
        == Some(expected)
}

fn truncate_utf8_bytes(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }
    let mut boundary = max_bytes;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
}

fn strip_xml_tags(xml: &str) -> String {
    let mut output = String::new();
    let mut in_tag = false;
    for character in xml.chars() {
        match character {
            '<' => {
                in_tag = true;
                output.push(' ');
            }
            '>' => in_tag = false,
            _ if !in_tag => output.push(character),
            _ => {}
        }
        if output.len() >= MAX_EXTRACTED_TEXT_BYTES {
            break;
        }
    }
    output
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

pub(super) fn printable_text(raw: &str) -> String {
    raw.chars()
        .take(MAX_EXTRACTED_TEXT_BYTES)
        .map(|character| {
            if character.is_control() && !character.is_whitespace() {
                ' '
            } else {
                character
            }
        })
        .collect()
}
