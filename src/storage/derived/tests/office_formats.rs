use std::io::Write as _;

use super::super::{extract_office_text, office_format, OfficeDocumentFormat};

#[test]
fn extracts_open_document_content_xml_without_reading_unrelated_archive_entries() {
    let mut archive = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut archive);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer.start_file("mimetype", options).unwrap();
        writer
            .write_all(b"application/vnd.oasis.opendocument.text")
            .unwrap();
        writer.start_file("content.xml", options).unwrap();
        writer
            .write_all(b"<office:document-content><text:p>odf fixture needle</text:p></office:document-content>")
            .unwrap();
        writer.start_file("styles.xml", options).unwrap();
        writer
            .write_all(b"<style>unrelated style text</style>")
            .unwrap();
        writer.finish().unwrap();
    }

    let extracted =
        extract_office_text(archive.get_ref(), OfficeDocumentFormat::OpenDocument).unwrap();
    assert!(extracted.contains("odf fixture needle"));
    assert!(!extracted.contains("unrelated style text"));
}

#[test]
fn office_extensions_keep_archive_and_legacy_binary_contracts_distinct() {
    assert!(matches!(
        office_format("docx"),
        Some(OfficeDocumentFormat::OpenXml)
    ));
    assert!(matches!(
        office_format("odt"),
        Some(OfficeDocumentFormat::OpenDocument)
    ));
    assert!(matches!(
        office_format("doc"),
        Some(OfficeDocumentFormat::LegacyBinary)
    ));
}
