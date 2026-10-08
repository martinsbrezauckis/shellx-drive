(function registerDriveFileTypes(global) {
  "use strict";

  const { fileExtension } = global.ShellXDriveFormat;

  const FILE_TYPE_TABLE = {
    png: ["i-file-image", "--ft-image", "Image", "image", true],
    jpg: ["i-file-image", "--ft-image", "Image", "image", true],
    jpeg: ["i-file-image", "--ft-image", "Image", "image", true],
    gif: ["i-file-image", "--ft-image", "Image", "image", true],
    webp: ["i-file-image", "--ft-image", "Image", "image", true],
    bmp: ["i-file-image", "--ft-image", "Image", "image", true],
    ico: ["i-file-image", "--ft-image", "Icon", "image", true],
    svg: ["i-file-image", "--ft-image", "Vector image", "none", false],
    pdf: ["i-file-pdf", "--ft-pdf", "PDF", "pdf", false],
    mp4: ["i-file-video", "--ft-video", "Video", "video", false],
    webm: ["i-file-video", "--ft-video", "Video", "video", false],
    mov: ["i-file-video", "--ft-video", "Video", "video", false],
    mkv: ["i-file-video", "--ft-video", "Video", "none", false],
    mp3: ["i-file-audio", "--ft-audio", "Audio", "audio", false],
    wav: ["i-file-audio", "--ft-audio", "Audio", "audio", false],
    ogg: ["i-file-audio", "--ft-audio", "Audio", "audio", false],
    m4a: ["i-file-audio", "--ft-audio", "Audio", "none", false],
    md: ["i-file-md", "--ft-md", "Markdown", "markdown", false],
    markdown: ["i-file-md", "--ft-md", "Markdown", "markdown", false],
    txt: ["i-file-text", "--ft-doc", "Text", "text", false],
    log: ["i-file-text", "--ft-doc", "Log", "text", false],
    rtf: ["i-file-text", "--ft-doc", "Document", "text", false],
    doc: ["i-file-text", "--ft-doc", "Document", "none", false],
    docx: ["i-file-text", "--ft-doc", "Document", "none", false],
    odt: ["i-file-text", "--ft-doc", "Document", "none", false],
    ppt: ["i-file-text", "--ft-doc", "Presentation", "none", false],
    pptx: ["i-file-text", "--ft-doc", "Presentation", "none", false],
    odp: ["i-file-text", "--ft-doc", "Presentation", "none", false],
    csv: ["i-file-sheet", "--ft-sheet", "CSV", "text", false],
    tsv: ["i-file-sheet", "--ft-sheet", "Data", "text", false],
    xls: ["i-file-sheet", "--ft-sheet", "Spreadsheet", "none", false],
    xlsx: ["i-file-sheet", "--ft-sheet", "Spreadsheet", "none", false],
    ods: ["i-file-sheet", "--ft-sheet", "Spreadsheet", "none", false],
    json: ["i-file-code", "--ft-code", "JSON", "text", false],
    xml: ["i-file-code", "--ft-code", "XML", "text", false],
    yaml: ["i-file-code", "--ft-code", "YAML", "text", false],
    yml: ["i-file-code", "--ft-code", "YAML", "text", false],
    toml: ["i-file-code", "--ft-code", "Config", "text", false],
    js: ["i-file-code", "--ft-code", "Code", "text", false],
    ts: ["i-file-code", "--ft-code", "Code", "text", false],
    py: ["i-file-code", "--ft-code", "Code", "text", false],
    rs: ["i-file-code", "--ft-code", "Code", "text", false],
    go: ["i-file-code", "--ft-code", "Code", "text", false],
    sh: ["i-file-code", "--ft-code", "Script", "text", false],
    css: ["i-file-code", "--ft-code", "Stylesheet", "text", false],
    html: ["i-file-code", "--ft-code", "HTML", "none", false],
    zip: ["i-file-zip", "--ft-zip", "Archive", "none", false],
    tar: ["i-file-zip", "--ft-zip", "Archive", "none", false],
    gz: ["i-file-zip", "--ft-zip", "Archive", "none", false],
    "7z": ["i-file-zip", "--ft-zip", "Archive", "none", false],
    rar: ["i-file-zip", "--ft-zip", "Archive", "none", false],
  };

  function fileTypeInfo(file) {
    if (!file || file.kind === "folder") {
      return {
        icon: "i-folder", hue: "--ft-folder", hueClass: "ft-folder", label: "Folder",
        preview: "none", previewable: false, editable: false, thumb: false, isFolder: true,
      };
    }
    const ext = fileExtension(file);
    const entry = FILE_TYPE_TABLE[ext] || [
      "i-file", "--ft-generic", ext ? ext.toUpperCase() : "File", "none", false,
    ];
    const preview = entry[3];
    return {
      icon: entry[0], hue: entry[1], hueClass: entry[1].slice(2), label: entry[2], preview,
      previewable: preview !== "none",
      editable: ["text", "markdown"].includes(preview),
      thumb: Boolean(entry[4]),
      isFolder: false,
    };
  }


  global.ShellXDriveFileTypes = Object.freeze({ fileTypeInfo });
})(window);
