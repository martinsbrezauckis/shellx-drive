use super::*;
use std::io::Write as _;

mod office_formats;

#[test]
fn office_extraction_rejects_oversized_compressed_xml() {
    let mut archive = Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut archive);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        writer.start_file("word/document.xml", options).unwrap();
        writer
            .write_all(&vec![b'a'; MAX_OFFICE_ENTRY_BYTES as usize + 1])
            .unwrap();
        writer.finish().unwrap();
    }

    let error = extract_office_text(archive.get_ref(), OfficeDocumentFormat::OpenXml).unwrap_err();
    assert!(error.contains("too large") || error.contains("compression ratio"));
}

#[test]
fn office_extraction_truncates_multibyte_text_on_a_character_boundary() {
    let prefix = "a".repeat(MAX_EXTRACTED_TEXT_BYTES - 3);
    let xml = format!("<w:t>{prefix}€</w:t>");
    let mut archive = Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut archive);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer.start_file("word/document.xml", options).unwrap();
        writer.write_all(xml.as_bytes()).unwrap();
        writer.finish().unwrap();
    }

    let extracted = extract_office_text(archive.get_ref(), OfficeDocumentFormat::OpenXml).unwrap();
    assert!(extracted.len() <= MAX_EXTRACTED_TEXT_BYTES);
    assert!(extracted.is_char_boundary(extracted.len()));
}

#[test]
fn office_entry_count_is_rejected_from_end_record_before_archive_open() {
    let mut archive = Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut archive);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for index in 0..=MAX_OFFICE_ARCHIVE_ENTRIES {
            writer
                .start_file(format!("word/entry-{index}.xml"), options)
                .unwrap();
        }
        writer.finish().unwrap();
    }

    let error = extract_office_text(archive.get_ref(), OfficeDocumentFormat::OpenXml).unwrap_err();
    assert!(error.contains("too many entries"), "{error}");
}

#[test]
fn image_preview_rejects_oversized_declared_dimensions_before_decode() {
    let source = image::RgbaImage::from_pixel(1, 1, image::Rgba([0, 0, 0, 255]));
    let mut encoded = Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(source)
        .write_to(&mut encoded, ImageFormat::Png)
        .unwrap();
    let mut png = encoded.into_inner();
    png[16..20].copy_from_slice(&9000u32.to_be_bytes());
    png[20..24].copy_from_slice(&9000u32.to_be_bytes());
    let crc = test_crc32(&png[12..29]);
    png[29..33].copy_from_slice(&crc.to_be_bytes());

    let temp = tempfile::tempdir().unwrap();
    let error = generate_image_preview(temp.path(), &png).unwrap_err();
    assert!(error.contains("dimensions exceed"), "{error}");
}

#[test]
fn normalized_search_text_is_bounded() {
    let input = format!("{} final", "word ".repeat(MAX_EXTRACTED_TEXT_BYTES));
    let normalized = non_empty_text(input).unwrap();
    assert!(normalized.len() <= MAX_EXTRACTED_TEXT_BYTES);
}

fn test_crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}
