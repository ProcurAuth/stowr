//! The properties of an Office Open XML package (Word, Excel, PowerPoint, Visio) for the details of an object.
//!
//! The reader opens the central directory over exact ranges and reads the small parts `docProps/core.xml`,
//! `docProps/app.xml` and `docProps/custom.xml`. It counts the parts of the package by name. It never opens the
//! main document, the cells of a sheet, a slide or a page of a drawing, so the details stay small for a large file.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;

use http::HeaderMap;

use super::package::{Fault, Package, Truncate, open_sized_source, parse_entry};
use super::util::{parse_i64, parse_integer};
use super::xml::{XmlEvent, XmlFault, XmlReader, attribute};
use crate::archive::zip::{ZipEntry, ZipReader};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::instance::Instance;
use crate::pv_media::MediaSourceMetadata;

/// The largest package: 8 GiB.
pub const MAX_OBJECT_BYTES: i64 = 8 << 30;
/// The most parts of a package.
pub const MAX_ARCHIVE_FILES: usize = 20_000;
/// The most bytes of a part of the properties.
pub const MAX_PROPERTIES_XML_BYTES: u64 = 1 << 20;
/// The most custom properties.
pub const MAX_CUSTOM_PROPERTIES: usize = 256;

/// The kind of a package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfficeFamily {
    /// Word.
    Word,
    /// Excel.
    Spreadsheet,
    /// PowerPoint.
    Presentation,
    /// Visio.
    Visio,
}

/// The properties of a package, with what the read of the object found.
#[derive(Debug, Default)]
pub struct OfficeSummary {
    /// The label of the container.
    pub container: String,
    /// The properties by label. Empty when the package has none.
    pub properties: BTreeMap<String, String>,
    /// The headers of the first answer of the storage.
    pub headers: HeaderMap,
    /// The size of the object.
    pub size: i64,
    /// The bytes that the reads took from the storage.
    pub bytes_read: i64,
    /// The requests that the reads sent to the storage.
    pub requests: u64,
}

/// The family of an extension, or `None` for an extension that is not of Office Open XML.
pub fn family_of(extension: &str) -> Option<OfficeFamily> {
    if is_word_extension(extension) {
        Some(OfficeFamily::Word)
    } else if is_spreadsheet_extension(extension) {
        Some(OfficeFamily::Spreadsheet)
    } else if is_presentation_extension(extension) {
        Some(OfficeFamily::Presentation)
    } else if is_visio_extension(extension) {
        Some(OfficeFamily::Visio)
    } else {
        None
    }
}

/// True for DOCX, DOCM, DOTX and DOTM.
pub fn is_word_extension(extension: &str) -> bool {
    matches!(
        extension.trim().to_lowercase().as_str(),
        "docx" | "docm" | "dotx" | "dotm"
    )
}

/// True for XLSX, XLSM, XLTX, XLTM and XLAM.
pub fn is_spreadsheet_extension(extension: &str) -> bool {
    matches!(
        extension.trim().to_lowercase().as_str(),
        "xlsx" | "xlsm" | "xltx" | "xltm" | "xlam"
    )
}

/// True for the presentation extensions of Office Open XML.
pub fn is_presentation_extension(extension: &str) -> bool {
    matches!(
        extension.trim().to_lowercase().as_str(),
        "pptx" | "pptm" | "potx" | "potm" | "ppsx" | "ppsm" | "ppam" | "sldx" | "sldm"
    )
}

/// True for the Visio extensions of Office Open XML.
pub fn is_visio_extension(extension: &str) -> bool {
    matches!(
        extension.trim().to_lowercase().as_str(),
        "vsdx" | "vsdm" | "vssx" | "vssm" | "vstx" | "vstm"
    )
}

/// The label of the container from the extension.
pub fn container_label(extension: &str) -> String {
    let trimmed = extension.trim();
    match trimmed.to_lowercase().as_str() {
        "docx" => "Microsoft Word Open XML",
        "docm" => "Microsoft Word macro-enabled document",
        "dotx" => "Microsoft Word template",
        "dotm" => "Microsoft Word macro-enabled template",
        "xlsx" => "Microsoft Excel workbook",
        "xlsm" => "Microsoft Excel macro-enabled workbook",
        "xltx" => "Microsoft Excel template",
        "xltm" => "Microsoft Excel macro-enabled template",
        "xlam" => "Microsoft Excel add-in",
        "pptx" => "Microsoft PowerPoint presentation",
        "pptm" => "Microsoft PowerPoint macro-enabled presentation",
        "potx" => "Microsoft PowerPoint template",
        "potm" => "Microsoft PowerPoint macro-enabled template",
        "ppsx" => "Microsoft PowerPoint slide show",
        "ppsm" => "Microsoft PowerPoint macro-enabled slide show",
        "ppam" => "Microsoft PowerPoint add-in",
        "sldx" => "Microsoft PowerPoint slide",
        "sldm" => "Microsoft PowerPoint macro-enabled slide",
        "vsdx" => "Microsoft Visio drawing",
        "vsdm" => "Microsoft Visio macro-enabled drawing",
        "vssx" => "Microsoft Visio stencil",
        "vssm" => "Microsoft Visio macro-enabled stencil",
        "vstx" => "Microsoft Visio template",
        "vstm" => "Microsoft Visio macro-enabled template",
        _ => return trimmed.to_uppercase(),
    }
    .to_owned()
}

/// The labels of the elements of `docProps/core.xml`.
fn core_label(name: &str) -> Option<&'static str> {
    Some(match name {
        "title" => "Title",
        "subject" => "Subject",
        "creator" => "Author",
        "keywords" => "Keywords",
        "description" => "Description",
        "lastModifiedBy" => "Last modified by",
        "revision" => "Revision",
        "created" => "Created",
        "modified" => "Modified",
        "category" => "Category",
        "contentStatus" => "Content status",
        "language" => "Language",
        "identifier" => "Identifier",
        "version" => "Version",
        _ => return None,
    })
}

/// The labels of the elements of `docProps/app.xml`.
fn app_label(name: &str) -> Option<&'static str> {
    Some(match name {
        "Application" => "Application",
        "AppVersion" => "Application version",
        "Company" => "Company",
        "Manager" => "Manager",
        "Template" => "Template",
        "Pages" => "Pages",
        "Words" => "Words",
        "Characters" => "Characters",
        "CharactersWithSpaces" => "Characters with spaces",
        "Paragraphs" => "Paragraphs",
        "Lines" => "Lines",
        "TotalTime" => "Editing time (minutes)",
        "DocSecurity" => "Document security",
        "ScaleCrop" => "Scale crop",
        "SharedDoc" => "Shared document",
        "HyperlinksChanged" => "Hyperlinks changed",
        "Slides" => "Slides",
        "HiddenSlides" => "Hidden slides",
        "Notes" => "Notes slides",
        "MMClips" => "Multimedia clips",
        "PresentationFormat" => "Presentation format",
        _ => return None,
    })
}

/// The value of a property: trimmed, and the whole numbers of the counters in their short form.
pub fn normalize_property_value(name: &str, value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        return String::new();
    }
    if matches!(
        name,
        "Pages"
            | "Words"
            | "Characters"
            | "CharactersWithSpaces"
            | "Paragraphs"
            | "Lines"
            | "TotalTime"
            | "Revision"
            | "DocSecurity"
            | "Slides"
            | "HiddenSlides"
            | "Notes"
            | "MMClips"
    ) && let Some(parsed) = parse_i64(value)
    {
        return parsed.to_string();
    }
    value.to_owned()
}

fn properties_parse_error(code: &str, message: &str) -> Error {
    Error::api(422, code, message)
}

/// The values of the elements of a part that have a label.
fn read_labeled_values<R: Read>(
    reader: R,
    labels: fn(&str) -> Option<&'static str>,
) -> std::result::Result<Vec<(&'static str, String)>, XmlFault> {
    let mut xml = XmlReader::new(reader);
    let mut found: Vec<(&'static str, String)> = Vec::new();
    while let Some(event) = xml.next_event()? {
        let XmlEvent::Start { name, .. } = event else {
            continue;
        };
        let Some(label) = labels(&name) else {
            continue;
        };
        let value = xml.element_text()?;
        let value = normalize_property_value(&name, &value);
        if !value.is_empty() {
            found.push((label, value));
        }
    }
    Ok(found)
}

async fn read_properties_part(
    package: &Package,
    part: &ZipEntry,
    destination: &mut BTreeMap<String, String>,
    labels: fn(&str) -> Option<&'static str>,
) -> Result<()> {
    if part.size > MAX_PROPERTIES_XML_BYTES {
        return Err(Error::api(
            413,
            "document_properties_too_large",
            "the Word document properties exceed the preview limit",
        ));
    }
    let stream = package.reader.open_entry(part).await.map_err(|_| {
        properties_parse_error(
            "invalid_docx_properties",
            "the Word document properties could not be opened",
        )
    })?;
    let parsed = parse_entry(stream, move |reader| {
        read_labeled_values(Truncate::new(reader, MAX_PROPERTIES_XML_BYTES + 1), labels).map_err(Fault::from)
    })
    .await?;
    let found = parsed.map_err(|_| {
        properties_parse_error(
            "invalid_docx_properties",
            "the Word document properties could not be parsed",
        )
    })?;
    for (label, value) in found {
        destination.insert(label.to_owned(), value);
    }
    Ok(())
}

fn custom_parse_error() -> Error {
    properties_parse_error(
        "invalid_office_properties",
        "the Office custom properties could not be parsed",
    )
}

/// The custom properties of `docProps/custom.xml`: the name and the first value with text, in the order of the
/// document. At most 256 properties are read.
fn read_custom_values<R: Read>(reader: R) -> std::result::Result<Vec<(String, String)>, XmlFault> {
    let mut xml = XmlReader::new(reader);
    let mut found: Vec<(String, String)> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    while let Some(event) = xml.next_event()? {
        let XmlEvent::Start { name, attrs } = event else {
            continue;
        };
        if name != "property" {
            continue;
        }
        if seen.len() >= MAX_CUSTOM_PROPERTIES {
            return Ok(found);
        }
        let property_name = attribute(&attrs, "name").unwrap_or("").trim().to_owned();
        let mut value = String::new();
        loop {
            match xml.next_event()? {
                None => return Err(XmlFault::Syntax("unexpected end of the data".to_owned())),
                Some(XmlEvent::Start { .. }) => {
                    let text = xml.element_text()?;
                    let text = text.trim();
                    if !text.is_empty() {
                        value = text.to_owned();
                        break;
                    }
                }
                Some(XmlEvent::End { name }) => {
                    if name == "property" {
                        break;
                    }
                }
                Some(XmlEvent::Text(_)) => {}
            }
        }
        if !property_name.is_empty() && !value.is_empty() && seen.insert(property_name.clone()) {
            found.push((property_name, value));
        }
    }
    Ok(found)
}

async fn read_custom_part(
    package: &Package,
    part: &ZipEntry,
    destination: &mut BTreeMap<String, String>,
) -> Result<()> {
    if part.size > MAX_PROPERTIES_XML_BYTES {
        return Err(Error::api(
            413,
            "office_properties_too_large",
            "the Office custom properties exceed the metadata limit",
        ));
    }
    let stream = package.reader.open_entry(part).await.map_err(|_| {
        properties_parse_error(
            "invalid_office_properties",
            "the Office custom properties could not be opened",
        )
    })?;
    let parsed = parse_entry(stream, |reader| {
        read_custom_values(Truncate::new(reader, MAX_PROPERTIES_XML_BYTES + 1)).map_err(Fault::from)
    })
    .await?;
    let found = parsed.map_err(|_| custom_parse_error())?;
    for (name, value) in found {
        destination.entry(format!("Custom - {name}")).or_insert(value);
    }
    Ok(())
}

fn count_prefix(counts: &mut BTreeMap<&'static str, i64>, name: &str, prefix: &str, label: &'static str) {
    if name.starts_with(prefix) && !name.ends_with('/') {
        *counts.entry(label).or_insert(0) += 1;
    }
}

fn count_exact_name(counts: &mut BTreeMap<&'static str, i64>, name: &str, expected: &str, label: &'static str) {
    if name == expected {
        *counts.entry(label).or_insert(0) += 1;
    }
}

/// Count a part that is `prefix`, a whole number and `.xml`, and not in a folder `_rels`.
fn count_numbered(counts: &mut BTreeMap<&'static str, i64>, name: &str, prefix: &str, label: &'static str) {
    if name.contains("/_rels/") {
        return;
    }
    let Some(suffix) = name.strip_prefix(prefix).and_then(|rest| rest.strip_suffix(".xml")) else {
        return;
    };
    if parse_i64(suffix).is_some() {
        *counts.entry(label).or_insert(0) += 1;
    }
}

/// Add the counts of the parts of the package and the marks of the macros and of the signatures.
pub fn add_package_structure_properties(
    properties: &mut BTreeMap<String, String>,
    names: &[String],
    family: OfficeFamily,
) {
    let mut counts: BTreeMap<&'static str, i64> = BTreeMap::new();
    let mut macros = false;
    let mut signed = false;
    for name in names {
        let lowered = name.to_lowercase();
        let lower = lowered.as_str();
        if lower.ends_with("/vbaproject.bin") {
            macros = true;
        }
        if lower.starts_with("_xmlsignatures/") {
            signed = true;
        }
        match family {
            OfficeFamily::Word => {
                count_prefix(&mut counts, lower, "word/media/", "Images");
                count_prefix(&mut counts, lower, "word/embeddings/", "Embedded objects");
                count_prefix(&mut counts, lower, "word/charts/", "Charts");
                count_numbered(&mut counts, lower, "word/header", "Headers");
                count_numbered(&mut counts, lower, "word/footer", "Footers");
                count_exact_name(&mut counts, lower, "word/comments.xml", "Comments");
                count_exact_name(&mut counts, lower, "word/footnotes.xml", "Footnotes");
                count_exact_name(&mut counts, lower, "word/endnotes.xml", "Endnotes");
            }
            OfficeFamily::Spreadsheet => {
                count_numbered(&mut counts, lower, "xl/worksheets/sheet", "Worksheets");
                count_prefix(&mut counts, lower, "xl/media/", "Images");
                count_prefix(&mut counts, lower, "xl/embeddings/", "Embedded objects");
                count_numbered(&mut counts, lower, "xl/charts/chart", "Charts");
                count_numbered(&mut counts, lower, "xl/pivottables/pivottable", "Pivot tables");
                count_prefix(&mut counts, lower, "xl/externallinks/", "External links");
                count_prefix(&mut counts, lower, "xl/comments", "Comment parts");
                count_exact_name(&mut counts, lower, "xl/connections.xml", "Data connections");
            }
            OfficeFamily::Presentation => {
                count_numbered(&mut counts, lower, "ppt/slides/slide", "Slides");
                count_numbered(&mut counts, lower, "ppt/notesslides/notesslide", "Notes slides");
                count_numbered(&mut counts, lower, "ppt/comments/comment", "Comment parts");
                count_prefix(&mut counts, lower, "ppt/media/", "Media files");
                count_prefix(&mut counts, lower, "ppt/embeddings/", "Embedded objects");
                count_numbered(&mut counts, lower, "ppt/charts/chart", "Charts");
                count_numbered(&mut counts, lower, "ppt/slidemasters/slidemaster", "Slide masters");
                count_numbered(&mut counts, lower, "ppt/slidelayouts/slidelayout", "Slide layouts");
                count_prefix(&mut counts, lower, "ppt/theme/", "Themes");
            }
            OfficeFamily::Visio => {
                count_numbered(&mut counts, lower, "visio/pages/page", "Pages");
                count_numbered(&mut counts, lower, "visio/masters/master", "Masters");
                count_prefix(&mut counts, lower, "visio/media/", "Media files");
                count_prefix(&mut counts, lower, "visio/embeddings/", "Embedded objects");
                count_prefix(&mut counts, lower, "visio/theme/", "Themes");
            }
        }
    }
    for (label, count) in counts {
        if count <= 0 {
            continue;
        }
        if let Some(existing) = properties.get(label) {
            let (parsed, valid) = parse_integer(&existing.replace(',', ""));
            if valid && parsed > 0 {
                continue;
            }
        }
        properties.insert(label.to_owned(), count.to_string());
    }
    if macros {
        properties.insert("Macros".to_owned(), "Yes".to_owned());
    }
    if signed {
        properties.insert("Digital signatures".to_owned(), "Yes".to_owned());
    }
}

/// Add the properties of `source` that `destination` has not, without the empty values.
pub fn merge_office_properties(
    mut destination: BTreeMap<String, String>,
    source: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    for (key, value) in source {
        if value.trim().is_empty() {
            continue;
        }
        destination.entry(key.clone()).or_insert_with(|| value.clone());
    }
    destination
}

/// The properties of a package of Office Open XML. It reads the central directory and the small parts of the
/// properties only.
pub async fn inspect_office_properties(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    extension: &str,
    listed: &MediaSourceMetadata,
    family: OfficeFamily,
) -> Result<OfficeSummary> {
    let mut result = OfficeSummary {
        container: container_label(extension),
        ..OfficeSummary::default()
    };
    let (source, size) = open_sized_source(ctx, instance, key, listed.size, &listed.etag).await?;
    let Some(size) = size.filter(|size| *size > 0) else {
        return Err(Error::api(
            422,
            "unknown_office_size",
            "Office document details require a known non-zero object size",
        ));
    };
    if size > MAX_OBJECT_BYTES {
        return Err(Error::api(
            413,
            "office_document_too_large",
            format!(
                "Office document details are limited to objects smaller than {} GiB",
                MAX_OBJECT_BYTES >> 30
            ),
        ));
    }
    let reader = match ZipReader::open(source, MAX_ARCHIVE_FILES).await {
        Ok(reader) => reader,
        Err(error) if crate::archive::zip::is_format_error(&error) => {
            return Err(Error::api(
                422,
                "invalid_office_package",
                "the object is not a valid Office Open XML package",
            ));
        }
        Err(error) if error.has_code(crate::archive::zip::CODE_TOO_MANY_ENTRIES) => {
            return Err(Error::api(
                413,
                "office_archive_too_large",
                "the Office package contains too many archive members",
            ));
        }
        Err(error) => return Err(error),
    };
    let package = Package::new(reader);
    if let Some(part) = package.part("docProps/core.xml") {
        read_properties_part(&package, part, &mut result.properties, core_label).await?;
    }
    if let Some(part) = package.part("docProps/app.xml") {
        read_properties_part(&package, part, &mut result.properties, app_label).await?;
    }
    if let Some(part) = package.part("docProps/custom.xml") {
        read_custom_part(&package, part, &mut result.properties).await?;
    }
    add_package_structure_properties(&mut result.properties, package.names(), family);
    result.headers = package.reader.source.headers();
    result.size = package.reader.source.size_or_zero();
    result.bytes_read = package.reader.source.bytes_read();
    result.requests = package.reader.source.request_count();
    Ok(result)
}

/// The properties of a Word package. It is [`inspect_office_properties`] for the family Word.
pub async fn inspect_word_properties(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    extension: &str,
    listed: &MediaSourceMetadata,
) -> Result<OfficeSummary> {
    inspect_office_properties(ctx, instance, key, extension, listed, OfficeFamily::Word).await
}

/// The package properties of an Office Open XML file (Word, Excel, PowerPoint, Visio) for the details.
pub async fn office_properties(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    extension: &str,
) -> Result<BTreeMap<String, String>> {
    let Some(family) = family_of(extension) else {
        return Err(Error::api(
            400,
            "unsupported_office_package",
            "this extension is not an Office Open XML package",
        ));
    };
    let listed = MediaSourceMetadata {
        size: -1,
        ..MediaSourceMetadata::default()
    };
    let summary = inspect_office_properties(ctx, instance, key, extension, &listed, family).await?;
    Ok(summary.properties)
}

#[cfg(test)]
#[path = "office_tests.rs"]
mod tests;
