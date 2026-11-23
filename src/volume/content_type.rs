//! The content type of a file of a volume. A file has no metadata of S3: the type comes from the extension of the
//! name. The release image has no `/etc/mime.types`, so the tables here are the whole source.

/// The content type of a folder key (`<folder>/`) in a HEAD answer.
pub const FOLDER_CONTENT_TYPE: &str = "application/x-directory";

/// The content types of common text and archive files.
const TEXT_TYPES: &[(&str, &str)] = &[
    (".txt", "text/plain; charset=utf-8"),
    (".log", "text/plain; charset=utf-8"),
    (".md", "text/markdown; charset=utf-8"),
    (".csv", "text/csv; charset=utf-8"),
    (".tsv", "text/tab-separated-values; charset=utf-8"),
    (".yaml", "application/yaml"),
    (".yml", "application/yaml"),
    (".toml", "application/toml"),
    (".zip", "application/zip"),
    (".gz", "application/gzip"),
    (".tar", "application/x-tar"),
];

/// The content types of the files that the previews open: media, images, cards, mail and certificates.
const PREVIEW_TYPES: &[(&str, &str)] = &[
    (".mp4", "video/mp4"),
    (".m4v", "video/x-m4v"),
    (".mov", "video/quicktime"),
    (".webm", "video/webm"),
    (".mkv", "video/x-matroska"),
    (".mxf", "application/mxf"),
    (".avi", "video/x-msvideo"),
    (".ogv", "video/ogg"),
    (".mpg", "video/mpeg"),
    (".mpeg", "video/mpeg"),
    (".m2ts", "video/mp2t"),
    (".mts", "video/mp2t"),
    (".ts", "video/mp2t"),
    (".vob", "video/dvd"),
    (".mp3", "audio/mpeg"),
    (".m4a", "audio/mp4"),
    (".aac", "audio/aac"),
    (".flac", "audio/flac"),
    (".wav", "audio/wav"),
    (".ogg", "audio/ogg"),
    (".opus", "audio/ogg; codecs=opus"),
    (".aif", "audio/aiff"),
    (".aiff", "audio/aiff"),
    (".jpg", "image/jpeg"),
    (".jpeg", "image/jpeg"),
    (".png", "image/png"),
    (".gif", "image/gif"),
    (".webp", "image/webp"),
    (".avif", "image/avif"),
    (".svg", "image/svg+xml"),
    (".bmp", "image/bmp"),
    (".ico", "image/x-icon"),
    (".vcf", "text/vcard; charset=utf-8"),
    (".vcard", "text/vcard; charset=utf-8"),
    (".ics", "text/calendar; charset=utf-8"),
    (".ifb", "text/calendar; charset=utf-8"),
    (".eml", "message/rfc822"),
    (".mime", "message/rfc822"),
    (".pem", "application/x-pem-file"),
    (".crt", "application/x-x509-ca-cert"),
    (".cer", "application/pkix-cert"),
    (".der", "application/pkix-cert"),
    (".tif", "image/tiff"),
    (".tiff", "image/tiff"),
    (".pdf", "application/pdf"),
];

/// The content types of the web files that a browser knows.
const WEB_TYPES: &[(&str, &str)] = &[
    (".css", "text/css; charset=utf-8"),
    (".htm", "text/html; charset=utf-8"),
    (".html", "text/html; charset=utf-8"),
    (".js", "text/javascript; charset=utf-8"),
    (".mjs", "text/javascript; charset=utf-8"),
    (".json", "application/json"),
    (".wasm", "application/wasm"),
    (".xml", "text/xml; charset=utf-8"),
];

/// The extension of a key with its dot: the part of the last name from its last dot. An empty text for a name
/// without a dot.
fn extension(key: &str) -> &str {
    let name = key.rsplit('/').next().unwrap_or(key);
    match name.rfind('.') {
        Some(index) => &name[index..],
        None => "",
    }
}

fn lookup(table: &[(&'static str, &'static str)], extension: &str) -> Option<&'static str> {
    table
        .iter()
        .find(|(known, _)| *known == extension)
        .map(|(_, value)| *value)
}

/// The content type of a key from the extension of its name.
pub fn content_type(key: &str) -> &'static str {
    let extension = extension(key).to_lowercase();
    lookup(TEXT_TYPES, &extension)
        .or_else(|| lookup(PREVIEW_TYPES, &extension))
        .or_else(|| lookup(WEB_TYPES, &extension))
        .unwrap_or("application/octet-stream")
}
